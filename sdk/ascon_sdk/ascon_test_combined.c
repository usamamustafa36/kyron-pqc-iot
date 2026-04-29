#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ascon_api.h"

int main() {
    // Key and nonce must be same for encryption and decryption
    const uint8_t key[16] = {0};
    const uint8_t nonce[16] = {1};

    const uint8_t plaintext[] = "Hello ASCON!";
    const uint8_t associated_data[] = "AD";

    uint8_t ciphertext[128];
    unsigned long long ciphertext_len = 0;

    // Encrypt
    int ret = ascon_encrypt(ciphertext, &ciphertext_len,
                            plaintext, sizeof(plaintext) - 1,
                            associated_data, sizeof(associated_data) - 1,
                            nonce, key);
    if (ret != 0) {
        printf("Encryption failed!\n");
        return 1;
    }

    printf("Encryption successful.\n");
    printf("Ciphertext (%llu bytes): ", ciphertext_len);
    for (unsigned long long i = 0; i < ciphertext_len; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt
    uint8_t decrypted[128];
    unsigned long long decrypted_len = 0;

    ret = ascon_decrypt(decrypted, &decrypted_len,
                        ciphertext, ciphertext_len,
                        associated_data, sizeof(associated_data) - 1,
                        nonce, key);
    if (ret != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    printf("Decryption successful.\n");
    printf("Decrypted text: %.*s\n", (int)decrypted_len, decrypted);

    // Verify match
    if (decrypted_len == sizeof(plaintext) - 1 &&
        memcmp(plaintext, decrypted, decrypted_len) == 0) {
        printf("Test passed: decrypted text matches plaintext\n");
    } else {
        printf("Test failed: decrypted text does NOT match plaintext\n");
    }

    return 0;
}
