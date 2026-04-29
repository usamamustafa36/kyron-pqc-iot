#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "dilithium_api.h"

// Helper to print byte arrays as hex
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    const char *message = "Hello from Device 1";
    size_t msglen = strlen(message);

    // Buffers for Device 1
    uint8_t pk1[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t sk1[DILITHIUM_SECRET_KEY_BYTES];
    uint8_t sig1[DILITHIUM_SIGNATURE_BYTES];
    size_t sig1_len;

    // Buffers for Device 2
    uint8_t pk2[DILITHIUM_PUBLIC_KEY_BYTES];
    uint8_t sk2[DILITHIUM_SECRET_KEY_BYTES];

    // Device 1 keypair generation
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk1, sk1) != 0) {
        printf("Device 1: Keypair generation failed\n");
        return 1;
    }

    // Device 2 keypair generation
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk2, sk2) != 0) {
        printf("Device 2: Keypair generation failed\n");
        return 1;
    }

    // Device 1 signs the message
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig1, &sig1_len, (const uint8_t *)message, msglen, sk1) != 0) {
        printf("Device 1: Signing failed\n");
        return 1;
    }

    printf("Device 1: Signature created\n");

    print_hex("Device 1 Public Key", pk1, DILITHIUM_PUBLIC_KEY_BYTES);
    print_hex("Device 1 Secret Key", sk1, DILITHIUM_SECRET_KEY_BYTES);
    print_hex("Device 1 Signature", sig1, sig1_len);

    print_hex("Device 2 Public Key", pk2, DILITHIUM_PUBLIC_KEY_BYTES);
    print_hex("Device 2 Secret Key", sk2, DILITHIUM_SECRET_KEY_BYTES);

    // Device 2 tries to verify Device 1's signature with Device 1's public key (should pass)
    int res1 = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig1, sig1_len, (const uint8_t *)message, msglen, pk1);
    printf("Device 2 verifying with Device 1's public key: %s\n", (res1 == 0) ? "PASSED" : "FAILED");

    // Device 2 tries to verify Device 1's signature with Device 2's public key (should fail)
    int res2 = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig1, sig1_len, (const uint8_t *)message, msglen, pk2);
    printf("Device 2 verifying with Device 2's public key: %s\n", (res2 == 0) ? "PASSED" : "FAILED");

    return 0;
}

