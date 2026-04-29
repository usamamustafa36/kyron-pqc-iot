#include <stdio.h>
#include "pqc_device.h"

int main(void) {
    if (pqc_init() != 0) return 1;

    const char *msg = "Hello IoT device!";
    if (pqc_encrypt_message((const uint8_t*)msg, strlen(msg)) != 0) return 1;

    if (pqc_decrypt_message() != 0) return 1;

    printf("Decrypted message: %.*s\n", (int)pqc_get_decrypted_length(), pqc_get_decrypted_message());
    return 0;
}

