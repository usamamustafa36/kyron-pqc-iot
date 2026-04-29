/*
 * mqtt_pqc_client.c  —  Kyron two-device deployment
 *
 * Key exchange is done over MQTT handshake topics (no /tmp/ files).
 * Flow per message: Kyber session key → Dilithium sign → ASCON encrypt.
 */

#include "mqtt_pqc_client.h"
#include "randombytes.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ── Handshake state (filled by _on_handshake_msg) ───────────────────── */
typedef struct {
    uint8_t sub_kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t pub_dil_pk  [DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t kyber_ct    [KYBER_CIPHERTEXT_BYTES];
    int     got_sub_kyber_pk;
    int     got_pub_dil_pk;
    int     got_kyber_ct;
} hs_state_t;

static hs_state_t g_hs;

/* ── Data-callback state (filled after handshake) ────────────────────── */
typedef struct {
    mqtt_pqc_ctx_t  *ctx;
    mqtt_pqc_msg_cb  user_cb;
    uint8_t          peer_dil_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    int              have_peer_pk;
} cb_data_t;

static cb_data_t g_cbd;

/* ── Helpers ──────────────────────────────────────────────────────────── */

/* Publish a zero-length retained message to clear stale retained data. */
static void _clear_retained(struct mosquitto *mosq, const char *topic)
{
    mosquitto_publish(mosq, NULL, topic, 0, NULL, 1, true);
}

/* Drive the mosquitto network layer for up to ms milliseconds. */
static void _loop_ms(struct mosquitto *mosq, int ms)
{
    mosquitto_loop(mosq, ms, 1);
}

/* ── Handshake message callback ───────────────────────────────────────── */
static void _on_handshake_msg(struct mosquitto              *mosq,
                              void                          *userdata,
                              const struct mosquitto_message *msg)
{
    (void)mosq; (void)userdata;
    if (!msg || !msg->payload || msg->payloadlen <= 0) return;

    if (strcmp(msg->topic, PQC_TOPIC_SUB_KYBER_PK) == 0 &&
        msg->payloadlen == KYBER_PUBLIC_KEY_BYTES) {
        memcpy(g_hs.sub_kyber_pk, msg->payload, KYBER_PUBLIC_KEY_BYTES);
        g_hs.got_sub_kyber_pk = 1;
        printf("[HS] Got subscriber Kyber PK\n");
    } else if (strcmp(msg->topic, PQC_TOPIC_PUB_DIL_PK) == 0 &&
               msg->payloadlen == DILITHIUM_PUBLIC_KEY_BYTES) {
        memcpy(g_hs.pub_dil_pk, msg->payload, DILITHIUM_PUBLIC_KEY_BYTES);
        g_hs.got_pub_dil_pk = 1;
        printf("[HS] Got publisher Dilithium PK\n");
    } else if (strcmp(msg->topic, PQC_TOPIC_KYBER_CT) == 0 &&
               msg->payloadlen == KYBER_CIPHERTEXT_BYTES) {
        memcpy(g_hs.kyber_ct, msg->payload, KYBER_CIPHERTEXT_BYTES);
        g_hs.got_kyber_ct = 1;
        printf("[HS] Got Kyber ciphertext\n");
    }
}

/* ── Data message callback (installed after handshake) ───────────────── */
static void _on_data_msg(struct mosquitto              *mosq,
                         void                          *userdata,
                         const struct mosquitto_message *msg)
{
    (void)mosq;
    cb_data_t      *cbd = (cb_data_t *)userdata;
    mqtt_pqc_ctx_t *ctx = cbd->ctx;

    if (!msg || msg->payloadlen < (int)ASCON_NONCE_BYTES) {
        fprintf(stderr, "[DATA] Message too short — ignored\n");
        return;
    }

    const uint8_t *payload    = (const uint8_t *)msg->payload;
    size_t         plen       = (size_t)msg->payloadlen;
    const uint8_t *nonce      = payload;
    const uint8_t *ciphertext = payload + ASCON_NONCE_BYTES;
    unsigned long long ct_len = (unsigned long long)(plen - ASCON_NONCE_BYTES);

    uint8_t            plaintext[MQTT_PQC_MAX_PAYLOAD];
    unsigned long long pt_len = 0;
    uint8_t            signature[DILITHIUM_SIGNATURE_BYTES];

    if (pqc_ascon_decrypt_full_message(plaintext, &pt_len,
                                       signature, DILITHIUM_SIGNATURE_BYTES,
                                       ciphertext, ct_len,
                                       nonce,
                                       ctx->session.session_key) != 0) {
        fprintf(stderr, "[DATA] Decryption failed on '%s'\n", msg->topic);
        return;
    }

    if (cbd->have_peer_pk) {
        if (pqc_verify_message(plaintext, (size_t)pt_len,
                               signature, DILITHIUM_SIGNATURE_BYTES,
                               cbd->peer_dil_pk) != 0) {
            fprintf(stderr, "[DATA] Signature INVALID on '%s' — dropped\n",
                    msg->topic);
            return;
        }
        printf("[DATA] Signature OK\n");
    } else {
        printf("[DATA] (No peer PK — signature check skipped)\n");
    }

    if (cbd->user_cb)
        cbd->user_cb(ctx, msg->topic, plaintext, (size_t)pt_len);
}

/* ═══════════════════════════════════════════════════════════════════════
   PUBLIC API
   ═══════════════════════════════════════════════════════════════════════ */

/* ── mqtt_pqc_init ────────────────────────────────────────────────────── */
int mqtt_pqc_init(mqtt_pqc_ctx_t *ctx,
                  const char     *client_id,
                  const char     *broker,
                  int             port)
{
    if (!ctx || !client_id || !broker) return -1;

    memset(ctx, 0, sizeof(*ctx));
    strncpy(ctx->client_id,   client_id, sizeof(ctx->client_id)   - 1);
    strncpy(ctx->broker_host, broker,    sizeof(ctx->broker_host) - 1);
    ctx->broker_port = port;

    if (pqc_init_wrapper() != 0) {
        fprintf(stderr, "[PQC] pqc_init_wrapper failed\n");
        return -1;
    }

    if (pqc_kyber_keypair(ctx->session.kyber_pk, ctx->session.kyber_sk) != 0) {
        fprintf(stderr, "[PQC] Kyber keygen failed\n");
        return -1;
    }

    if (pqc_dilithium_keypair() != 0) {
        fprintf(stderr, "[PQC] Dilithium keygen failed\n");
        return -1;
    }
    memcpy(ctx->session.dil_pk, pqc_dilithium_get_pk(), DILITHIUM_PUBLIC_KEY_BYTES);
    memcpy(ctx->session.dil_sk, pqc_dilithium_get_sk(), DILITHIUM_SECRET_KEY_BYTES);

    ctx->session.session_ready = 0;
    ctx->connected             = 0;

    mosquitto_lib_init();
    ctx->mosq = mosquitto_new(client_id, true, NULL);
    if (!ctx->mosq) {
        fprintf(stderr, "[MQTT] mosquitto_new failed\n");
        return -1;
    }

    printf("[PQC] '%s' initialised. Kyber + Dilithium keys generated.\n", client_id);
    return 0;
}

/* ── mqtt_pqc_handshake_publisher ─────────────────────────────────────── */
int mqtt_pqc_handshake_publisher(mqtt_pqc_ctx_t *ctx)
{
    if (!ctx) return -1;

    memset(&g_hs, 0, sizeof(g_hs));

    /* Install handshake callback */
    mosquitto_message_callback_set(ctx->mosq, _on_handshake_msg);
    mosquitto_user_data_set(ctx->mosq, NULL);

    /* Connect to broker */
    printf("[PUB-HS] Connecting to broker %s:%d ...\n",
           ctx->broker_host, ctx->broker_port);
    int rc = mosquitto_connect(ctx->mosq, ctx->broker_host, ctx->broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[PUB-HS] Connect failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    ctx->connected = 1;
    printf("[PUB-HS] Connected.\n");

    /* Clear any stale retained messages from a previous run */
    _clear_retained(ctx->mosq, PQC_TOPIC_PUB_DIL_PK);
    _clear_retained(ctx->mosq, PQC_TOPIC_KYBER_CT);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);

    /* Publish our Dilithium PK so subscriber can verify our signatures */
    mosquitto_publish(ctx->mosq, NULL, PQC_TOPIC_PUB_DIL_PK,
                      DILITHIUM_PUBLIC_KEY_BYTES, ctx->session.dil_pk, 1, true);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);
    printf("[PUB-HS] Published Dilithium PK.\n");

    /* Subscribe to subscriber's Kyber PK */
    mosquitto_subscribe(ctx->mosq, NULL, PQC_TOPIC_SUB_KYBER_PK, 1);
    printf("[PUB-HS] Waiting for subscriber's Kyber PK (up to %ds)...\n",
           MQTT_PQC_HANDSHAKE_TIMEOUT_S);

    int waited = 0;
    while (!g_hs.got_sub_kyber_pk && waited < MQTT_PQC_HANDSHAKE_TIMEOUT_S) {
        _loop_ms(ctx->mosq, 1000);
        waited++;
        printf("[PUB-HS]   ... %ds\n", waited);
    }
    if (!g_hs.got_sub_kyber_pk) {
        fprintf(stderr, "[PUB-HS] Timeout — no subscriber Kyber PK received\n");
        return -1;
    }

    /* Kyber encapsulate → derive session key */
    uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];
    if (pqc_kyber_encapsulate(kyber_ct, shared_secret, g_hs.sub_kyber_pk) != 0) {
        fprintf(stderr, "[PUB-HS] Kyber encapsulation failed\n");
        return -1;
    }
    memcpy(ctx->session.session_key, shared_secret, KYBER_SHARED_SECRET_BYTES);

    /* Publish Kyber ciphertext so subscriber can decapsulate */
    mosquitto_publish(ctx->mosq, NULL, PQC_TOPIC_KYBER_CT,
                      KYBER_CIPHERTEXT_BYTES, kyber_ct, 1, true);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);
    printf("[PUB-HS] Published Kyber ciphertext.\n");

    ctx->session.session_ready = 1;
    printf("[PUB-HS] Handshake complete. Session key established.\n");
    return 0;
}

/* ── mqtt_pqc_handshake_subscriber ───────────────────────────────────── */
int mqtt_pqc_handshake_subscriber(mqtt_pqc_ctx_t *ctx, mqtt_pqc_msg_cb user_cb)
{
    if (!ctx) return -1;

    memset(&g_hs, 0, sizeof(g_hs));

    /* Install handshake callback */
    mosquitto_message_callback_set(ctx->mosq, _on_handshake_msg);
    mosquitto_user_data_set(ctx->mosq, NULL);

    /* Connect to broker */
    printf("[SUB-HS] Connecting to broker %s:%d ...\n",
           ctx->broker_host, ctx->broker_port);
    int rc = mosquitto_connect(ctx->mosq, ctx->broker_host, ctx->broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[SUB-HS] Connect failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    ctx->connected = 1;
    printf("[SUB-HS] Connected.\n");

    /* Clear stale retained subscriber key from previous run */
    _clear_retained(ctx->mosq, PQC_TOPIC_SUB_KYBER_PK);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);

    /* Subscribe to publisher's handshake messages BEFORE publishing our key
       so we don't miss any retained messages already on the broker. */
    mosquitto_subscribe(ctx->mosq, NULL, PQC_TOPIC_PUB_DIL_PK, 1);
    mosquitto_subscribe(ctx->mosq, NULL, PQC_TOPIC_KYBER_CT,   1);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);

    /* Publish our Kyber PK so publisher can encapsulate to us */
    mosquitto_publish(ctx->mosq, NULL, PQC_TOPIC_SUB_KYBER_PK,
                      KYBER_PUBLIC_KEY_BYTES, ctx->session.kyber_pk, 1, true);
    for (int i = 0; i < 5; i++) _loop_ms(ctx->mosq, 100);
    printf("[SUB-HS] Published Kyber PK. Waiting for publisher (up to %ds)...\n",
           MQTT_PQC_HANDSHAKE_TIMEOUT_S);

    int waited = 0;
    while ((!g_hs.got_pub_dil_pk || !g_hs.got_kyber_ct) &&
           waited < MQTT_PQC_HANDSHAKE_TIMEOUT_S) {
        _loop_ms(ctx->mosq, 1000);
        waited++;
        printf("[SUB-HS]   ... %ds  (dil_pk=%d, kyber_ct=%d)\n",
               waited, g_hs.got_pub_dil_pk, g_hs.got_kyber_ct);
    }
    if (!g_hs.got_pub_dil_pk || !g_hs.got_kyber_ct) {
        fprintf(stderr, "[SUB-HS] Timeout — publisher did not complete handshake\n");
        return -1;
    }

    /* Kyber decapsulate → recover session key */
    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];
    if (pqc_kyber_decapsulate(shared_secret, g_hs.kyber_ct,
                              ctx->session.kyber_sk) != 0) {
        fprintf(stderr, "[SUB-HS] Kyber decapsulation failed\n");
        return -1;
    }
    memcpy(ctx->session.session_key, shared_secret, KYBER_SHARED_SECRET_BYTES);
    ctx->session.session_ready = 1;
    printf("[SUB-HS] Handshake complete. Session key established.\n");

    /* Switch to data callback and subscribe to data topic */
    memset(&g_cbd, 0, sizeof(g_cbd));
    g_cbd.ctx        = ctx;
    g_cbd.user_cb    = user_cb;
    memcpy(g_cbd.peer_dil_pk, g_hs.pub_dil_pk, DILITHIUM_PUBLIC_KEY_BYTES);
    g_cbd.have_peer_pk = 1;

    mosquitto_user_data_set(ctx->mosq, &g_cbd);
    mosquitto_message_callback_set(ctx->mosq, _on_data_msg);
    mosquitto_subscribe(ctx->mosq, NULL, PQC_DATA_TOPIC, 1);
    printf("[SUB-HS] Subscribed to data topic '%s'. Ready.\n", PQC_DATA_TOPIC);

    return 0;
}

/* ── mqtt_pqc_publish ─────────────────────────────────────────────────── */
int mqtt_pqc_publish(mqtt_pqc_ctx_t *ctx,
                     const char     *topic,
                     const uint8_t  *message,
                     size_t          msg_len)
{
    if (!ctx || !topic || !message) return -1;
    if (!ctx->session.session_ready) {
        fprintf(stderr, "[PQC] Session not ready — call handshake first\n");
        return -1;
    }

    /* 1. Sign */
    uint8_t signature[DILITHIUM_SIGNATURE_BYTES];
    size_t  sig_len = 0;
    if (pqc_sign_message(message, msg_len, signature, &sig_len) != 0) {
        fprintf(stderr, "[PQC] Signing failed\n");
        return -1;
    }

    /* 2. Random nonce */
    uint8_t nonce[ASCON_NONCE_BYTES];
    randombytes(nonce, ASCON_NONCE_BYTES);

    /* 3. Encrypt: ciphertext = ASCON(message ‖ signature) */
    uint8_t            ct[MQTT_PQC_MAX_PAYLOAD];
    unsigned long long ct_len = 0;
    if (pqc_ascon_encrypt_full_message(ct, &ct_len,
                                       message, msg_len,
                                       signature, sig_len,
                                       nonce,
                                       ctx->session.session_key) != 0) {
        fprintf(stderr, "[PQC] Encryption failed\n");
        return -1;
    }

    /* 4. Wire payload: nonce ‖ ciphertext */
    uint8_t payload[MQTT_PQC_MAX_PAYLOAD + ASCON_NONCE_BYTES];
    memcpy(payload,                   nonce, ASCON_NONCE_BYTES);
    memcpy(payload + ASCON_NONCE_BYTES, ct,  (size_t)ct_len);
    size_t payload_len = ASCON_NONCE_BYTES + (size_t)ct_len;

    /* 5. Publish */
    int rc = mosquitto_publish(ctx->mosq, NULL, topic,
                               (int)payload_len, payload, 1, false);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MQTT] Publish failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }

    printf("[MQTT] Published %zu bytes (encrypted) to '%s'\n", payload_len, topic);
    return 0;
}

/* ── mqtt_pqc_loop ────────────────────────────────────────────────────── */
void mqtt_pqc_loop(mqtt_pqc_ctx_t *ctx)
{
    if (!ctx) return;
    printf("[MQTT] Listening for messages. Press Ctrl+C to stop.\n");
    mosquitto_loop_forever(ctx->mosq, -1, 1);
}

/* ── mqtt_pqc_cleanup ─────────────────────────────────────────────────── */
void mqtt_pqc_cleanup(mqtt_pqc_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->mosq) {
        mosquitto_disconnect(ctx->mosq);
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
    }
    mosquitto_lib_cleanup();
    printf("[MQTT] Cleaned up.\n");
}
