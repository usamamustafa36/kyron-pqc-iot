#ifndef MQTT_PQC_CLIENT_H
#define MQTT_PQC_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <mosquitto.h>

/* Include PQC wrapper FIRST so all constants are defined before we use them */
#include "pqc_test_wrapper.h"

/* Pull in the SDK API headers directly for the size constants */
#include "kyber/api.h"
#include "dilithium/api.h"
#include "ascon/api.h"

/* -------------------------------------------------------
   Safety fallbacks: if SDK headers don't define these,
   we use Kyber-768 / Dilithium3 defaults.
   Check your kyber/api.h to confirm the numbers match.
   ------------------------------------------------------- */
#ifndef KYBER_PUBLIC_KEY_BYTES
  #define KYBER_PUBLIC_KEY_BYTES      1184
#endif
#ifndef KYBER_SECRET_KEY_BYTES
  #define KYBER_SECRET_KEY_BYTES      2400
#endif
#ifndef KYBER_CIPHERTEXT_BYTES
  #define KYBER_CIPHERTEXT_BYTES      1088
#endif
#ifndef KYBER_SHARED_SECRET_BYTES
  #define KYBER_SHARED_SECRET_BYTES     32
#endif
#ifndef DILITHIUM_PUBLIC_KEY_BYTES
  #define DILITHIUM_PUBLIC_KEY_BYTES  1952
#endif
#ifndef DILITHIUM_SECRET_KEY_BYTES
  #define DILITHIUM_SECRET_KEY_BYTES  4000
#endif
#ifndef DILITHIUM_SIGNATURE_BYTES
  #define DILITHIUM_SIGNATURE_BYTES   3293
#endif
#ifndef ASCON_KEY_BYTES
  #define ASCON_KEY_BYTES   16
#endif
#ifndef ASCON_NONCE_BYTES
  #define ASCON_NONCE_BYTES 16
#endif

/* -------------------------------------------------------
   Max sizes
   ------------------------------------------------------- */
#define MQTT_PQC_MAX_PAYLOAD  (PQC_MAX_BUFFER)
#define MQTT_PQC_TOPIC_LEN    256
#define MQTT_PQC_BROKER_LEN   128

/* -------------------------------------------------------
   Session context — one per device
   ------------------------------------------------------- */
typedef struct {
    uint8_t kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t kyber_sk[KYBER_SECRET_KEY_BYTES];
    uint8_t session_key[KYBER_SHARED_SECRET_BYTES];
    uint8_t dil_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t dil_sk[DILITHIUM_SECRET_KEY_BYTES];
    int     session_ready;
} pqc_session_t;

/* -------------------------------------------------------
   MQTT client context
   ------------------------------------------------------- */
typedef struct {
    struct mosquitto *mosq;
    pqc_session_t    session;
    char             broker_host[MQTT_PQC_BROKER_LEN];
    int              broker_port;
    char             client_id[64];
} mqtt_pqc_ctx_t;

/* -------------------------------------------------------
   Callback: fired on each successfully decrypted message
   ------------------------------------------------------- */
typedef void (*mqtt_pqc_msg_cb)(mqtt_pqc_ctx_t *ctx,
                                const char     *topic,
                                const uint8_t  *plaintext,
                                size_t          len);

/* -------------------------------------------------------
   Public API
   ------------------------------------------------------- */
int  mqtt_pqc_init(mqtt_pqc_ctx_t *ctx,
                   const char     *client_id,
                   const char     *broker,
                   int             port);

int  mqtt_pqc_establish_session(mqtt_pqc_ctx_t *ctx,
                                const uint8_t  *peer_pk);

int  mqtt_pqc_accept_session(mqtt_pqc_ctx_t *ctx,
                             const uint8_t  *kyber_ct);

int  mqtt_pqc_connect_subscribe(mqtt_pqc_ctx_t  *ctx,
                                const char      *topic,
                                mqtt_pqc_msg_cb  cb);

int  mqtt_pqc_publish(mqtt_pqc_ctx_t *ctx,
                      const char     *topic,
                      const uint8_t  *message,
                      size_t          msg_len);

void mqtt_pqc_set_peer_pk(const uint8_t *peer_dil_pk);
void mqtt_pqc_loop(mqtt_pqc_ctx_t *ctx);
void mqtt_pqc_cleanup(mqtt_pqc_ctx_t *ctx);

#endif /* MQTT_PQC_CLIENT_H */
