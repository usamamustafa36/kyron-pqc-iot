#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pqc_device.h"   // single header for your SDK

int main(void) {
    printf("[IoT Device] Booting up...\n");

    if (pqc_init() != 0) {
        printf("[IoT Device] ERROR: SDK init failed.\n");
        return 1;
    }
    printf("[IoT Device] SDK initialized successfully.\n");

    // Example telemetry message
    const char *msg = "Hello from IoT sensor #01!";
    printf("[IoT Device] Preparing telemetry: \"%s\"\n", msg);

    // Encrypt before sending
    if (pqc_encrypt_message((const uint8_t*)msg, strlen(msg)) != 0) {
        printf("[IoT Device] ERROR: Encryption failed.\n");
        return 1;
    }
    printf("[IoT Device] Telemetry encrypted and ready for transmission.\n");

    // Decrypt as if received back from server
    if (pqc_decrypt_message() != 0) {
        printf("[IoT Device] ERROR: Decryption failed.\n");
        return 1;
    }

    printf("[IoT Device] Received secure response: \"%.*s\"\n",
           (int)pqc_get_decrypted_length(),
           pqc_get_decrypted_message());

    printf("[IoT Device] Communication cycle complete.\n");
    return 0;
}

