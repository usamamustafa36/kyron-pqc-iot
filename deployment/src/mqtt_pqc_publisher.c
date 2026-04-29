/*
 * mqtt_pqc_publisher.c  —  Kyron two-device deployment
 * Role: Publisher / IoT sensor  (runs on Raspberry Pi)
 *
 * Usage:  ./mqtt_pqc_publisher  <broker_ip>  [port]
 * Example on Pi:  ./mqtt_pqc_publisher 192.168.1.10 1883
 *
 * Start the subscriber (laptop) FIRST so its Kyber PK is waiting on the broker.
 */

#include "mqtt_pqc_client.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    /* ── 0. Parse broker address ─────────────────────────────────────── */
    const char *broker = (argc > 1) ? argv[1] : "127.0.0.1";
    int         port   = (argc > 2) ? atoi(argv[2]) : 1883;

    printf("=== Kyron MQTT Publisher ===\n");
    printf("Broker: %s:%d\n\n", broker, port);

    /* ── 1. Init: generate Kyber + Dilithium keys, create mosq client ── */
    mqtt_pqc_ctx_t pub;
    if (mqtt_pqc_init(&pub, "pqc_publisher", broker, port) != 0) {
        fprintf(stderr, "[PUB] Init failed\n");
        return 1;
    }

    /* ── 2. Run MQTT handshake (no /tmp/ files) ──────────────────────── */
    /*
     * Handshake sequence:
     *   a) Publisher publishes its Dilithium PK to pqc/handshake/pub_dil_pk
     *   b) Publisher waits for subscriber's Kyber PK on pqc/handshake/sub_kyber_pk
     *   c) Publisher Kyber-encapsulates → derives shared session key
     *   d) Publisher publishes Kyber ciphertext to pqc/handshake/kyber_ct
     *   → session_ready = 1
     */
    if (mqtt_pqc_handshake_publisher(&pub) != 0) {
        fprintf(stderr, "[PUB] Handshake failed — is subscriber running?\n");
        mqtt_pqc_cleanup(&pub);
        return 1;
    }

    printf("\n[PUB] Session established. Starting sensor data loop.\n\n");

    /* ── 3. Publish encrypted sensor readings every 3 seconds ────────── */
    int seq = 0;
    while (1) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "{\"device\":\"pi_sensor\",\"temp\":%.1f,\"humidity\":%.1f,\"seq\":%d}",
                 22.5 + (seq % 5) * 0.3,
                 55.0 + (seq % 3) * 1.2,
                 seq);

        printf("[PUB] seq=%d  payload=%s\n", seq, msg);

        if (mqtt_pqc_publish(&pub, PQC_DATA_TOPIC,
                             (const uint8_t *)msg, strlen(msg)) != 0) {
            fprintf(stderr, "[PUB] Publish failed — continuing\n");
        }

        /* Drive mosquitto network loop to flush outgoing packets */
        for (int i = 0; i < 5; i++)
            mosquitto_loop(pub.mosq, 100, 1);

        seq++;
        sleep(3);
    }

    mqtt_pqc_cleanup(&pub);
    return 0;
}
