/*
 * mqtt_pqc_subscriber.c
 *
 * Demo: Subscriber (receiver — runs on Ubuntu or second Raspberry Pi)
 *
 * What this does:
 *   1. Generates PQC keypairs
 *   2. Saves its own Kyber public key so publisher can load it
 *   3. Waits for publisher's Kyber ciphertext (/tmp/kyber_ct.bin)
 *   4. Decapsulates to recover the shared session key
 *   5. Subscribes and decrypts + verifies every incoming message
 *
 * Start this BEFORE the publisher.
 *
 * Place in: <your_project>/src/mqtt_pqc_subscriber.c
 */

#include "mqtt_pqc_client.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---- Callback: called for every successfully decrypted message ---- */
static void on_sensor_data(mqtt_pqc_ctx_t *ctx,
                           const char     *topic,
                           const uint8_t  *plaintext,
                           size_t          len)
{
    (void)ctx;
    printf("\n[SUB] *** Message received on '%s' ***\n", topic);
    printf("[SUB]     Decrypted payload (%zu bytes): %.*s\n",
           len, (int)len, (const char *)plaintext);
    printf("[SUB]     (Quantum-safe: Kyber session + Ascon encryption + Dilithium signature)\n");
}

int main(void)
{
    printf("=== Kyron MQTT Subscriber (Receiver) ===\n\n");

    /* ---- 1. Initialise PQC + MQTT ---- */
    mqtt_pqc_ctx_t sub;
    if (mqtt_pqc_init(&sub, "pqc_subscriber", "localhost", 1883) != 0) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }

    /* ---- 2. Save our Kyber public key so publisher can use it ---- */
    FILE *f = fopen("/tmp/sub_kyber_pk.bin", "wb");
    if (f) {
        fwrite(sub.session.kyber_pk, 1, KYBER_PUBLIC_KEY_BYTES, f);
        fclose(f);
        printf("[SUB] Saved our Kyber public key to /tmp/sub_kyber_pk.bin\n");
    }

    /* ---- 3. Wait for publisher's Kyber ciphertext ---- */
    printf("[SUB] Waiting for publisher's Kyber ciphertext at /tmp/kyber_ct.bin ...\n");
    uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
    while (1) {
        f = fopen("/tmp/kyber_ct.bin", "rb");
        if (f) {
            fread(kyber_ct, 1, KYBER_CIPHERTEXT_BYTES, f);
            fclose(f);
            printf("[SUB] Loaded Kyber ciphertext.\n");
            break;
        }
        sleep(1);
    }

    /* ---- 4. Recover shared session key (Kyber decapsulation) ---- */
    if (mqtt_pqc_accept_session(&sub, kyber_ct) != 0) {
        fprintf(stderr, "Session acceptance failed\n");
        return 1;
    }

    /* ---- 5. Load publisher's Dilithium public key for signature verification ---- */
    printf("[SUB] Waiting for publisher's Dilithium public key at /tmp/pub_dil_pk.bin ...\n");
    uint8_t pub_dil_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    while (1) {
        f = fopen("/tmp/pub_dil_pk.bin", "rb");
        if (f) {
            fread(pub_dil_pk, 1, DILITHIUM_PUBLIC_KEY_BYTES, f);
            fclose(f);
            printf("[SUB] Loaded publisher's Dilithium public key.\n");
            break;
        }
        sleep(1);
    }
    mqtt_pqc_set_peer_pk(pub_dil_pk);

    /* ---- 6. Connect to broker + subscribe ---- */
    if (mqtt_pqc_connect_subscribe(&sub,
                                   "sensors/temperature",
                                   on_sensor_data) != 0) {
        fprintf(stderr, "Connect/subscribe failed\n");
        return 1;
    }

    /* ---- 7. Block and process incoming messages ---- */
    mqtt_pqc_loop(&sub);   /* Ctrl+C to exit */

    mqtt_pqc_cleanup(&sub);
    return 0;
}
