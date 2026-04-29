#include <stdio.h>
#include <stdint.h>
#include "ascon/crypto_aead.h"
#include <string.h>
#include "ascon/ascon.h"

int main() {
    uint8_t key[16] = {0};
    uint8_t nonce[16] = {0};
    uint8_t msg[] = "ASCON PQC test message";
    uint8_t ciphertext[64] = {0};
    uint8_t decrypted[64] = {0};
    unsigned long long clen = 0, mlen = 0;

    // Encrypt
    crypto_aead_encrypt(ciphertext, &clen, msg, sizeof(msg), NULL, 0, NULL, nonce, key);
    printf("🔐 Encrypted (%llu bytes): ", clen);
    for (int i = 0; i < clen; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    // Decrypt
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ciphertext, clen, NULL, 0, nonce, key) == 0) {
        printf("✅ Decrypted: %.*s\n", (int)mlen, decrypted);
    } else {
        printf("❌ Decryption failed!\n");
    }

    return 0;
}
