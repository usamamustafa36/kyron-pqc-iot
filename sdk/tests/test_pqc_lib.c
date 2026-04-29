#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pqc_device.h"
#include "pqc_test_wrapper.h"

#define MSG "Hello Kyron!"
#define MSG_LEN (sizeof(MSG) - 1)

int main(void)
{
    int ret;

    printf("=== PQC Library Functional Test ===\n");

    // ----------------------------------------------------
    // 1. Initialize the PQC wrapper/device subsystem
    // ----------------------------------------------------
    ret = pqc_init();
    if (ret != 0) {
        printf("[ERROR] pqc_init failed (code %d)\n", ret);
        return 1;
    }
    printf("[OK] PQC subsystem initialized\n");

    // ----------------------------------------------------
    // 2. Generate Dilithium keypair
    // ----------------------------------------------------
    ret = pqc_dilithium_keypair();
    if (ret != 0) {
        printf("[ERROR] Dilithium keypair generation failed (code %d)\n", ret);
        return 1;
    }
    printf("[OK] Dilithium keypair generated\n");

    // ----------------------------------------------------
    // 3. Sign the message
    // ----------------------------------------------------
    ret = pqc_dilithium_sign((const uint8_t *)MSG, MSG_LEN);
    if (ret != 0) {
        printf("[ERROR] Dilithium signing failed (code %d)\n", ret);
        return 1;
    }
    printf("[OK] Message signed (sig len = %zu)\n",
           pqc_dilithium_get_siglen());

    // ----------------------------------------------------
    // 4. Encrypt message (+ internal signature/ciphertext buffers)
    // ----------------------------------------------------
    uint8_t nonce[ASCON_NONCE_BYTES] = {0};

    ret = pqc_encrypt_message((const uint8_t *)MSG, MSG_LEN, nonce);
    if (ret != 0) {
        printf("[ERROR] Encryption failed (code %d)\n", ret);
        return 1;
    }
    printf("[OK] Message encrypted, nonce generated\n");

    // ----------------------------------------------------
    // 5. Decrypt using returned nonce
    // ----------------------------------------------------
    ret = pqc_decrypt_message(nonce);
    if (ret != 0) {
        printf("[ERROR] Decryption failed (code %d)\n", ret);
        return 1;
    }

    // ----------------------------------------------------
    // 6. Retrieve decrypted plaintext
    // ----------------------------------------------------
    const uint8_t *decrypted = pqc_get_decrypted_message();
    size_t decrypted_len = pqc_get_decrypted_length();

    printf("[OK] Decrypted message length = %zu\n", decrypted_len);

    // ----------------------------------------------------
    // 7. Compare with original
    // ----------------------------------------------------
    if (decrypted_len != MSG_LEN ||
        memcmp(decrypted, MSG, MSG_LEN) != 0) {
        printf("[ERROR] Decrypted plaintext mismatch!\n");
        return 1;
    }
    printf("[OK] Decrypted plaintext matches original\n");

    // ----------------------------------------------------
    // 8. Verify Dilithium signature
    // ----------------------------------------------------
    ret = pqc_dilithium_verify(decrypted, decrypted_len);
    if (ret != 0) {
        printf("[ERROR] Signature verification failed (code %d)\n", ret);
        return 1;
    }
    printf("[OK] Signature verified successfully\n");

    printf("=== PQC Functional Test Passed ===\n");
    return 0;
}

