/*
 * mqtt_pqc_publisher.c  —  Sensor / publisher side
 *
 * Run AFTER the subscriber has started.
 * Change "localhost" to your broker IP when running on Raspberry Pi.
 *
 * Place in: <your_project>/src/mqtt_pqc_publisher.c
 */

#include "mqtt_pqc_client.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    printf("=== Kyron MQTT Publisher ===\n\n");

    /* 1. Init */
    mqtt_pqc_ctx_t pub;
    if (mqtt_pqc_init(&pub, "pqc_publisher", "localhost", 1883) != 0) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }

    /* 2. Save our Kyber public key so subscriber can load it */
    FILE *f = fopen("/tmp/pub_kyber_pk.bin", "wb");
    if (f) {
        fwrite(pub.session.kyber_pk, 1, KYBER_PUBLIC_KEY_BYTES, f);
        fclose(f);
        printf("[PUB] Kyber public key → /tmp/pub_kyber_pk.bin\n");
    }

    /* 3. Save our Dilithium public key so subscriber can verify signatures */
    f = fopen("/tmp/pub_dil_pk.bin", "wb");
    if (f) {
        fwrite(pub.session.dil_pk, 1, DILITHIUM_PUBLIC_KEY_BYTES, f);
        fclose(f);
        printf("[PUB] Dilithium public key → /tmp/pub_dil_pk.bin\n");
    }

    /* 4. Wait for subscriber's Kyber public key */
    printf("[PUB] Waiting for /tmp/sub_kyber_pk.bin ...\n");
    uint8_t sub_kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    while (1) {
        f = fopen("/tmp/sub_kyber_pk.bin", "rb");
        if (f) {
            fread(sub_kyber_pk, 1, KYBER_PUBLIC_KEY_BYTES, f);
            fclose(f);
            printf("[PUB] Loaded subscriber Kyber public key.\n");
            break;
        }
        sleep(1);
    }

    /* 5. Kyber encapsulation → writes /tmp/kyber_ct.bin */
    if (mqtt_pqc_establish_session(&pub, sub_kyber_pk) != 0) {
        fprintf(stderr, "Session failed\n");
        return 1;
    }

    /* 6. Connect to broker using our helper (handles mosquitto_connect internally) */
    /* We connect-only here (no subscription) */
    int rc = mosquitto_connect(pub.mosq, pub.broker_host, pub.broker_port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MQTT] Connect failed: %s\n", mosquitto_strerror(rc));
        return 1;
    }
    printf("[MQTT] Connected to broker.\n");

    /* Give subscriber time to also connect and be ready */
    sleep(2);

    /* 7. Publish encrypted readings */
    int seq = 0;
    while (1) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "{\"device\":\"pi_sensor_1\",\"temp\":%.1f,\"seq\":%d}",
                 22.5 + (seq % 5) * 0.3, seq);

        printf("\n[PUB] Sending → %s\n", msg);

        if (mqtt_pqc_publish(&pub, "sensors/temperature",
                             (const uint8_t *)msg, strlen(msg)) != 0) {
            fprintf(stderr, "[PUB] Publish failed\n");
        }

        /* Drive the mosquitto network loop briefly to flush outgoing messages */
        mosquitto_loop(pub.mosq, 100, 1);

        seq++;
        sleep(3);
    }

    mqtt_pqc_cleanup(&pub);
    return 0;
}
