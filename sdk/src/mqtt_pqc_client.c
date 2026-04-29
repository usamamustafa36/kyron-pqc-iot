/*
 * mqtt_pqc_client.c  —  Module 6: IoT Protocol Integration
 *
 * Flow:
 *   Kyber  → quantum-safe key exchange (shared secret)
 *   Dilithium → signs every outgoing message
 *   Ascon  → encrypts payload with the Kyber-derived key
 *
 * Place in: <your_project>/src/mqtt_pqc_client.c
 */

#include "mqtt_pqc_client.h"
#include "randombytes.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------
   Internal callback wrapper
   ------------------------------------------------------- */
typedef struct {
    mqtt_pqc_ctx_t  *ctx;
    mqtt_pqc_msg_cb  user_cb;
    uint8_t          peer_dil_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    int              have_peer_pk;
} _cb_data_t;

static _cb_data_t g_cb_data;

static void _on_message(struct mosquitto              *mosq,
                        void                          *userdata,
                        const struct mosquitto_message *msg)
{
    (void)mosq;
    _cb_data_t     *cbd = (_cb_data_t *)userdata;
    mqtt_pqc_ctx_t *ctx = cbd->ctx;

    if (!msg || msg->payloadlen < (int)ASCON_NONCE_BYTES) {
        fprintf(stderr, "[MQTT] Message too short — ignoring\n");
        return;
    }

    const uint8_t *payload    = (const uint8_t *)msg->payload;
    size_t         plen       = (size_t)msg->payloadlen;
    const uint8_t *nonce      = payload;
    const uint8_t *ciphertext = payload + ASCON_NONCE_BYTES;
    unsigned long long ct_len = (unsigned long long)(plen - ASCON_NONCE_BYTES);

    /* Decrypt */
    uint8_t            plaintext[MQTT_PQC_MAX_PAYLOAD];
    unsigned long long pt_len = 0;
    uint8_t            signature[DILITHIUM_SIGNATURE_BYTES];

    if (pqc_ascon_decrypt_full_message(plaintext, &pt_len,
                                       signature, DILITHIUM_SIGNATURE_BYTES,
                                       ciphertext, ct_len,
                                       nonce,
                                       ctx->session.session_key) != 0) {
        fprintf(stderr, "[PQC] Decryption failed on '%s'\n", msg->topic);
        return;
    }

    /* Verify signature */
    if (cbd->have_peer_pk) {
        if (pqc_verify_message(plaintext, (size_t)pt_len,
                               signature, DILITHIUM_SIGNATURE_BYTES,
                               cbd->peer_dil_pk) != 0) {
            fprintf(stderr, "[PQC] Signature INVALID on '%s' — dropping\n",
                    msg->topic);
            return;
        }
        printf("[PQC] Signature OK\n");
    } else {
        printf("[PQC] (No peer public key set — skipping signature check)\n");
    }

    if (cbd->user_cb)
        cbd->user_cb(ctx, msg->topic, plaintext, (size_t)pt_len);
}

/* -------------------------------------------------------
   mqtt_pqc_init
   ------------------------------------------------------- */
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

    /* Init PQC wrapper */
    if (pqc_init_wrapper() != 0) {
        fprintf(stderr, "[PQC] pqc_init_wrapper failed\n");
        return -1;
    }

    /* Kyber keypair */
    if (pqc_kyber_keypair(ctx->session.kyber_pk,
                          ctx->session.kyber_sk) != 0) {
        fprintf(stderr, "[PQC] Kyber keygen failed\n");
        return -1;
    }

    /* Dilithium keypair */
    if (pqc_dilithium_keypair() != 0) {
        fprintf(stderr, "[PQC] Dilithium keygen failed\n");
        return -1;
    }
    memcpy(ctx->session.dil_pk, pqc_dilithium_get_pk(), DILITHIUM_PUBLIC_KEY_BYTES);
    memcpy(ctx->session.dil_sk, pqc_dilithium_get_sk(), DILITHIUM_SECRET_KEY_BYTES);

    ctx->session.session_ready = 0;

    /* Mosquitto */
    mosquitto_lib_init();
    ctx->mosq = mosquitto_new(client_id, true, NULL);
    if (!ctx->mosq) {
        fprintf(stderr, "[MQTT] mosquitto_new failed\n");
        return -1;
    }

    printf("[PQC] '%s' ready. Kyber + Dilithium keys generated.\n", client_id);
    return 0;
}

/* -------------------------------------------------------
   mqtt_pqc_establish_session  (publisher side)
   ------------------------------------------------------- */
int mqtt_pqc_establish_session(mqtt_pqc_ctx_t *ctx,
                               const uint8_t  *peer_pk)
{
    if (!ctx || !peer_pk) return -1;

    uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];

    if (pqc_kyber_encapsulate(kyber_ct, shared_secret, peer_pk) != 0) {
        fprintf(stderr, "[PQC] Kyber encapsulation failed\n");
        return -1;
    }

    memcpy(ctx->session.session_key, shared_secret, KYBER_SHARED_SECRET_BYTES);
    ctx->session.session_ready = 1;

    /* Save ciphertext to file so subscriber can decapsulate */
    FILE *f = fopen("/tmp/kyber_ct.bin", "wb");
    if (f) {
        fwrite(kyber_ct, 1, KYBER_CIPHERTEXT_BYTES, f);
        fclose(f);
        printf("[PQC] Session ready. Kyber ciphertext → /tmp/kyber_ct.bin\n");
    }
    return 0;
}

/* -------------------------------------------------------
   mqtt_pqc_accept_session  (subscriber side)
   ------------------------------------------------------- */
int mqtt_pqc_accept_session(mqtt_pqc_ctx_t *ctx,
                            const uint8_t  *kyber_ct)
{
    if (!ctx || !kyber_ct) return -1;

    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];

    if (pqc_kyber_decapsulate(shared_secret, kyber_ct,
                              ctx->session.kyber_sk) != 0) {
        fprintf(stderr, "[PQC] Kyber decapsulation failed\n");
        return -1;
    }

    memcpy(ctx->session.session_key, shared_secret, KYBER_SHARED_SECRET_BYTES);
    ctx->session.session_ready = 1;
    printf("[PQC] Session accepted. Shared secret recovered.\n");
    return 0;
}

/* -------------------------------------------------------
   mqtt_pqc_publish
   Sign → Encrypt → Publish
   ------------------------------------------------------- */
int mqtt_pqc_publish(mqtt_pqc_ctx_t *ctx,
                     const char     *topic,
                     const uint8_t  *message,
                     size_t          msg_len)
{
    if (!ctx || !topic || !message) return -1;

    if (!ctx->session.session_ready) {
        fprintf(stderr, "[PQC] Session not ready.\n");
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

    /* 3. Encrypt */
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

    /* 4. Build payload: nonce | ciphertext */
    uint8_t payload[MQTT_PQC_MAX_PAYLOAD + ASCON_NONCE_BYTES];
    memcpy(payload,                  nonce, ASCON_NONCE_BYTES);
    memcpy(payload + ASCON_NONCE_BYTES, ct,  (size_t)ct_len);
    size_t payload_len = ASCON_NONCE_BYTES + (size_t)ct_len;

    /* 5. Publish */
    int rc = mosquitto_publish(ctx->mosq, NULL, topic,
                               (int)payload_len, payload, 1, false);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MQTT] Publish failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }

    printf("[MQTT] Published %zu encrypted bytes to '%s'\n", payload_len, topic);
    return 0;
}

/* -------------------------------------------------------
   mqtt_pqc_connect_subscribe
   ------------------------------------------------------- */
int mqtt_pqc_connect_subscribe(mqtt_pqc_ctx_t  *ctx,
                               const char      *topic,
                               mqtt_pqc_msg_cb  cb)
{
    if (!ctx || !topic) return -1;

    g_cb_data.ctx      = ctx;
    g_cb_data.user_cb  = cb;

    mosquitto_user_data_set(ctx->mosq, &g_cb_data);
    mosquitto_message_callback_set(ctx->mosq, _on_message);

    int rc = mosquitto_connect(ctx->mosq,
                               ctx->broker_host, ctx->broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MQTT] Connect to %s:%d failed: %s\n",
                ctx->broker_host, ctx->broker_port, mosquitto_strerror(rc));
        return -1;
    }
    printf("[MQTT] Connected to %s:%d\n", ctx->broker_host, ctx->broker_port);

    rc = mosquitto_subscribe(ctx->mosq, NULL, topic, 1);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MQTT] Subscribe failed: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    printf("[MQTT] Subscribed to '%s'\n", topic);
    return 0;
}

/* -------------------------------------------------------
   mqtt_pqc_set_peer_pk
   ------------------------------------------------------- */
void mqtt_pqc_set_peer_pk(const uint8_t *peer_dil_pk)
{
    if (!peer_dil_pk) return;
    memcpy(g_cb_data.peer_dil_pk, peer_dil_pk, DILITHIUM_PUBLIC_KEY_BYTES);
    g_cb_data.have_peer_pk = 1;
}

/* -------------------------------------------------------
   mqtt_pqc_loop  (blocking)
   ------------------------------------------------------- */
void mqtt_pqc_loop(mqtt_pqc_ctx_t *ctx)
{
    if (!ctx) return;
    printf("[MQTT] Listening... (Ctrl+C to stop)\n");
    mosquitto_loop_forever(ctx->mosq, -1, 1);
}

/* -------------------------------------------------------
   mqtt_pqc_cleanup
   ------------------------------------------------------- */
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
