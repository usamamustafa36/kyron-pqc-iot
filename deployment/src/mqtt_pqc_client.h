#ifndef MQTT_PQC_CLIENT_H
#define MQTT_PQC_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <mosquitto.h>

#include "pqc_test_wrapper.h"
#include "kyber/api.h"
#include "dilithium/api.h"
#include "ascon/api.h"

/* ── Key / buffer size fallbacks (Kyber-768, Dilithium3) ─────────────── */
#ifndef KYBER_PUBLIC_KEY_BYTES
  #define KYBER_PUBLIC_KEY_BYTES     1184
#endif
#ifndef KYBER_SECRET_KEY_BYTES
  #define KYBER_SECRET_KEY_BYTES     2400
#endif
#ifndef KYBER_CIPHERTEXT_BYTES
  #define KYBER_CIPHERTEXT_BYTES     1088
#endif
#ifndef KYBER_SHARED_SECRET_BYTES
  #define KYBER_SHARED_SECRET_BYTES    32
#endif
#ifndef DILITHIUM_PUBLIC_KEY_BYTES
  #define DILITHIUM_PUBLIC_KEY_BYTES 1952
#endif
#ifndef DILITHIUM_SECRET_KEY_BYTES
  #define DILITHIUM_SECRET_KEY_BYTES 4000
#endif
#ifndef DILITHIUM_SIGNATURE_BYTES
  #define DILITHIUM_SIGNATURE_BYTES  3293
#endif
#ifndef ASCON_KEY_BYTES
  #define ASCON_KEY_BYTES   16
#endif
#ifndef ASCON_NONCE_BYTES
  #define ASCON_NONCE_BYTES 16
#endif

/* ── MQTT topics ──────────────────────────────────────────────────────── */
/* Handshake topics — QoS 1, retained.  Cleared at startup each run.     */
#define PQC_TOPIC_SUB_KYBER_PK  "pqc/handshake/sub_kyber_pk"
#define PQC_TOPIC_PUB_DIL_PK    "pqc/handshake/pub_dil_pk"
#define PQC_TOPIC_KYBER_CT      "pqc/handshake/kyber_ct"
/* Data topic */
#define PQC_DATA_TOPIC          "sensors/temperature"

/* ── Misc limits ──────────────────────────────────────────────────────── */
#define MQTT_PQC_MAX_PAYLOAD  (PQC_MAX_BUFFER)
#define MQTT_PQC_TOPIC_LEN    256
#define MQTT_PQC_BROKER_LEN   128
#define MQTT_PQC_HANDSHAKE_TIMEOUT_S  60   /* seconds to wait for peer */

/* ── PQC session ──────────────────────────────────────────────────────── */
typedef struct {
    uint8_t kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t kyber_sk[KYBER_SECRET_KEY_BYTES];
    uint8_t session_key[KYBER_SHARED_SECRET_BYTES];
    uint8_t dil_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t dil_sk[DILITHIUM_SECRET_KEY_BYTES];
    int     session_ready;
} pqc_session_t;

/* ── MQTT client context ──────────────────────────────────────────────── */
typedef struct {
    struct mosquitto *mosq;
    pqc_session_t    session;
    char             broker_host[MQTT_PQC_BROKER_LEN];
    int              broker_port;
    char             client_id[64];
    int              connected;   /* 1 after mosquitto_connect succeeds */
} mqtt_pqc_ctx_t;

/* ── Callback: fired per successfully decrypted + verified message ────── */
typedef void (*mqtt_pqc_msg_cb)(mqtt_pqc_ctx_t *ctx,
                                const char     *topic,
                                const uint8_t  *plaintext,
                                size_t          len);

/* ── Core API ─────────────────────────────────────────────────────────── */
int  mqtt_pqc_init   (mqtt_pqc_ctx_t *ctx,
                      const char     *client_id,
                      const char     *broker,
                      int             port);

/* ── Handshake API (replaces /tmp file exchange) ─────────────────────── */

/*
 * Publisher side:
 *   Connects → publishes own Dilithium PK (retained)
 *   → waits for subscriber's Kyber PK
 *   → Kyber-encapsulates → publishes ciphertext (retained)
 *   → session_key set, session_ready = 1
 */
int  mqtt_pqc_handshake_publisher (mqtt_pqc_ctx_t *ctx);

/*
 * Subscriber side:
 *   Connects → publishes own Kyber PK (retained)
 *   → waits for publisher's Dil PK + Kyber ciphertext
 *   → Kyber-decapsulates → session_key set, session_ready = 1
 *   → installs data callback, subscribes to PQC_DATA_TOPIC
 */
int  mqtt_pqc_handshake_subscriber(mqtt_pqc_ctx_t *ctx, mqtt_pqc_msg_cb cb);

/* ── Data-plane API ───────────────────────────────────────────────────── */
int  mqtt_pqc_publish(mqtt_pqc_ctx_t *ctx,
                      const char     *topic,
                      const uint8_t  *message,
                      size_t          msg_len);

void mqtt_pqc_loop   (mqtt_pqc_ctx_t *ctx);   /* blocking */
void mqtt_pqc_cleanup(mqtt_pqc_ctx_t *ctx);

#endif /* MQTT_PQC_CLIENT_H */
