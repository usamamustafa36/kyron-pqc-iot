/*
 * mqtt_pqc_subscriber.c  —  Kyron two-device deployment
 * Role: Subscriber / backend receiver  (runs on Laptop)
 *
 * Usage:  ./mqtt_pqc_subscriber  <broker_ip>  [port]
 * Example on laptop:  ./mqtt_pqc_subscriber 127.0.0.1 1883
 *
 * Start this BEFORE the publisher so the Kyber PK is ready on the broker.
 */

#include "mqtt_pqc_client.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ── Data callback: called for every decrypted + verified message ─────── */
static void on_sensor_data(mqtt_pqc_ctx_t *ctx,
                           const char     *topic,
                           const uint8_t  *plaintext,
                           size_t          len)
{
    (void)ctx;
    printf("\n[SUB] *** Secure message on '%s' ***\n", topic);
    printf("[SUB]     Decrypted (%zu bytes): %.*s\n",
           len, (int)len, (const char *)plaintext);
    printf("[SUB]     Security: Kyber key exchange + ASCON encryption + Dilithium signature\n");

    /* Append decrypted JSON to feed file for the dashboard */
    FILE *f = fopen("/tmp/sensor_feed.jsonl", "a");
    if (f) {
        fprintf(f, "%.*s\n", (int)len, (const char *)plaintext);
        fclose(f);
    }
}

/* ─────────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    /* ── 0. Parse broker address ─────────────────────────────────────── */
    const char *broker = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port   = (argc > 2) ? atoi(argv[2]) : 1883;

    printf("=== Kyron MQTT Subscriber ===\n");
    printf("Broker: %s:%d\n\n", broker, port);

    /* ── 1. Init: generate Kyber + Dilithium keys ────────────────────── */
    mqtt_pqc_ctx_t sub;
    if (mqtt_pqc_init(&sub, "pqc_subscriber", broker, port) != 0) {
        fprintf(stderr, "[SUB] Init failed\n");
        return 1;
    }

    /* ── 2. Run MQTT handshake (no /tmp/ files) ──────────────────────── */
    /*
     * Handshake sequence:
     *   a) Subscriber publishes its Kyber PK to pqc/handshake/sub_kyber_pk
     *   b) Subscriber waits for publisher's Dilithium PK + Kyber ciphertext
     *   c) Subscriber Kyber-decapsulates → same shared session key as publisher
     *   d) Installs data callback, subscribes to sensors/temperature
     *   → session_ready = 1, ready to receive encrypted messages
     */
    if (mqtt_pqc_handshake_subscriber(&sub, on_sensor_data) != 0) {
        fprintf(stderr, "[SUB] Handshake failed\n");
        mqtt_pqc_cleanup(&sub);
        return 1;
    }

    printf("\n[SUB] Session established. Waiting for sensor data...\n\n");

    /* ── 3. Block and process incoming messages (Ctrl+C to stop) ─────── */
    mqtt_pqc_loop(&sub);

    mqtt_pqc_cleanup(&sub);
    return 0;
}
