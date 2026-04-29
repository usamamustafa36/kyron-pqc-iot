// receiver.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "dilithium_api.h"

#define PACKET_FILE "packet.bin"

int main() {
    FILE *f = fopen(PACKET_FILE, "rb");
    if (!f) { perror("open"); return 1; }

    // Read message length
    uint16_t msg_len;
    fread(&msg_len, sizeof(uint16_t), 1, f);

    // Read message
    uint8_t *msg = malloc(msg_len);
    fread(msg, 1, msg_len, f);

    // Read signature length
    uint16_t sig_len;
    fread(&sig_len, sizeof(uint16_t), 1, f);

    // Read signature
    uint8_t *sig = malloc(sig_len);
    fread(sig, 1, sig_len, f);

    // Read public key
    uint8_t pk[DILITHIUM_PUBLIC_KEY_BYTES];
    fread(pk, 1, DILITHIUM_PUBLIC_KEY_BYTES, f);

    fclose(f);

    // Verify signature
    if (dilithium_verify_with_pk(sig, sig_len, msg, msg_len, pk) == 0) {
        printf("Signature VALID\n");
        printf("Message: %.*s\n", msg_len, msg);
    } else {
        printf("Signature INVALID\n");
    }

    free(msg);
    free(sig);
    return 0;
}

