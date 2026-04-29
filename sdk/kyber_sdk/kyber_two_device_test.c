#include "kyber_api.h"
#include <stdio.h>
#include <string.h>

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t sk[KYBER_SECRET_KEY_BYTES];
    uint8_t ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t ss_enc[KYBER_SHARED_SECRET_BYTES];
    uint8_t ss_dec[KYBER_SHARED_SECRET_BYTES];

    // Generate keypair
    if (kyber_generate_keypair(pk, sk) != 0) {
        printf("Device 1: Keypair generation failed\n");
        return 1;
    }
    printf("Device 1: Generated keypair\n");
    print_hex("Public Key", pk, KYBER_PUBLIC_KEY_BYTES);
    print_hex("Secret Key", sk, KYBER_SECRET_KEY_BYTES);

    // Encapsulate
    if (kyber_encapsulate(ct, ss_enc, pk) != 0) {
        printf("Device 2: Encapsulation failed\n");
        return 1;
    }
    printf("Device 2: Encapsulated shared secret and ciphertext\n");
    print_hex("Ciphertext", ct, KYBER_CIPHERTEXT_BYTES);
    print_hex("Encapsulated Shared Secret", ss_enc, KYBER_SHARED_SECRET_BYTES);

    // Decapsulate
    if (kyber_decapsulate(ss_dec, ct, sk) != 0) {
        printf("Device 1: Decapsulation failed\n");
        return 1;
    }
    printf("Device 1: Decapsulated shared secret\n");
    print_hex("Decapsulated Shared Secret", ss_dec, KYBER_SHARED_SECRET_BYTES);

    // Compare shared secrets
    if (memcmp(ss_enc, ss_dec, KYBER_SHARED_SECRET_BYTES) == 0) {
        printf("Success: Shared secrets match!\n");
    } else {
        printf("Error: Shared secrets do NOT match.\n");
    }

    return 0;
}

