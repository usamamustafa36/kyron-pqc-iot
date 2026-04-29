#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "dilithium.h"

#define CRYPTO_PUBLICKEYBYTES 1312
#define CRYPTO_SECRETKEYBYTES 2528
#define CRYPTO_BYTES 2700  // Over-allocate for safety

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];  // Slightly over-allocated
    size_t siglen = 0;

    const uint8_t msg[] = "Kyron signing test";
    size_t msglen = sizeof(msg);

    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk) != 0) {
        printf("❌ Keypair generation failed!\n");
        return 1;
    }

    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, msglen, sk) != 0) {
        printf("❌ Signing failed!\n");
        return 1;
    }

    printf("📝 Signature length: %zu bytes\n", siglen);

    int valid = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, msglen, pk);
    if (valid == 0) {
        printf("✅ ML-DSA-44 (Dilithium2) signature verified!\n");
    } else {
        printf("❌ Signature verification failed.\n");
    }

    return 0;
}
