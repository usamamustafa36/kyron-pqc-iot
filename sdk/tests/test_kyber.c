#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"

int main() {
    uint8_t pk[800];   // CRYPTO_PUBLICKEYBYTES
    uint8_t sk[1632];  // CRYPTO_SECRETKEYBYTES
    uint8_t ct[768];   // CRYPTO_CIPHERTEXTBYTES
    uint8_t ss_enc[32];
    uint8_t ss_dec[32];

    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss_dec, ct, sk);

    if (memcmp(ss_enc, ss_dec, 32) == 0)
        printf("✅ Kyber512 test passed!\n");
    else
        printf("❌ Kyber512 test failed!\n");

    return 0;
}
