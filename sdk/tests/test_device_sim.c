#include "pqc_test_wrapper.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    printf("=== PQC SDK Full Test Simulation ===\n");

    // ------------------ Kyber ------------------
    uint8_t kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t kyber_sk[KYBER_SECRET_KEY_BYTES];
    uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t kyber_ss[KYBER_SHARED_SECRET_BYTES];
    uint8_t kyber_ss_dec[KYBER_SHARED_SECRET_BYTES];

    pqc_kyber_keypair(kyber_pk, kyber_sk);
    pqc_kyber_encapsulate(kyber_ct, kyber_ss, kyber_pk);
    pqc_kyber_decapsulate(kyber_ss_dec, kyber_ct, kyber_sk);

    if (memcmp(kyber_ss, kyber_ss_dec, KYBER_SHARED_SECRET_BYTES) == 0)
        printf("[Kyber] Shared secret successfully exchanged!\n");
    else
        printf("[Kyber] Shared secret mismatch!\n");

    // ------------------ Dilithium ------------------
    const char *message = "Hello IoT Device!";
    size_t msg_len = strlen(message);
    pqc_dilithium_keypair();
    int sign_ret = pqc_dilithium_sign((const uint8_t *)message, msg_len);
    if (sign_ret != 0) {
        printf("[Dilithium] Signing failed!\n");
        return -1;
    }

    const uint8_t *sig = pqc_dilithium_get_sig();
    size_t sig_len = pqc_dilithium_get_siglen();
    const uint8_t *pk = pqc_dilithium_get_pk();

    int verify_ret = pqc_dilithium_verify_with_pk(sig, sig_len, (const uint8_t *)message, msg_len, pk);
    if (verify_ret == 0)
        printf("[Dilithium] Signature verified successfully!\n");
    else
        printf("[Dilithium] Signature verification failed!\n");

    // ------------------ Ascon ------------------
    uint8_t ascon_key[ASCON_KEY_BYTES];
    uint8_t nonce[ASCON_NONCE_BYTES];
    randombytes(ascon_key, ASCON_KEY_BYTES);

    uint8_t ciphertext[PQC_MAX_BUFFER];
    unsigned long long ciphertext_len;

    int enc_ret = pqc_ascon_encrypt_full_message(ciphertext, &ciphertext_len,
                                                 (const uint8_t *)message, msg_len,
                                                 sig, sig_len,
                                                 nonce, ascon_key);
    if (enc_ret != 0) {
        printf("[Ascon] Encryption failed!\n");
        return -1;
    }
    printf("[Ascon] Message + signature encrypted successfully!\n");

    // ------------------ Receiver Side ------------------
    char decrypted_msg[256];
    uint8_t decrypted_sig[256];
    int dec_ret = pqc_ascon_decrypt_full_message((uint8_t *)decrypted_msg, msg_len,
                                                 decrypted_sig, sig_len,
                                                 ciphertext, ciphertext_len,
                                                 nonce, ascon_key);
    if (dec_ret != 0) {
        printf("[Ascon] Decryption failed!\n");
        return -1;
    }
    printf("[Ascon] Decrypted message: %s\n", decrypted_msg);

    // Verify signature again after decryption
    int verify_post_dec = pqc_dilithium_verify_with_pk(decrypted_sig, sig_len,
                                                       (const uint8_t *)decrypted_msg, msg_len,
                                                       pk);
    if (verify_post_dec == 0)
        printf("[Dilithium] Signature verified after decryption!\n");
    else
        printf("[Dilithium] Signature verification failed after decryption!\n");

    printf("=== PQC SDK Test Completed ===\n");
    return 0;
}

