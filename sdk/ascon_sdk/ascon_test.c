#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ascon_api.h"

int main(void) {
    const uint8_t key[16] = {0};
    const uint8_t nonce[16] = {1};
    const uint8_t plaintext[] = "Hello ASCON!";
    const uint8_t associated_data[] = "AD";

    uint8_t ciphertext[128];
    unsigned long long ciphertext_len = sizeof(ciphertext);

    uint8_t decrypted[128];
    unsigned long long decrypted_len = sizeof(decrypted);

    int ret;

    ret = ascon_encrypt(ciphertext, &ciphertext_len,
                        plaintext, (unsigned long long)strlen((const char *)plaintext),
                        associated_data, (unsigned long long)strlen((const char *)associated_data),
                        nonce, key);

    if (ret != 0) {
        printf("Encryption failed!\n");
        return 1;
    }

    ret = ascon_decrypt(decrypted, &decrypted_len,
                        ciphertext, ciphertext_len,
                        associated_data, (unsigned long long)strlen((const char *)associated_data),
                        nonce, key);

    if (ret != 0) {
        printf("Decryption failed!\n");
        return 1;
    }

    decrypted[decrypted_len] = '\0';

    printf("Decrypted text: %s\n", decrypted);

    if (memcmp(plaintext, decrypted, decrypted_len) == 0) {
        printf("Test passed: decrypted text matches plaintext\n");
    } else {
        printf("Test failed: decrypted text does NOT match plaintext\n");
    }

    return 0;
}

