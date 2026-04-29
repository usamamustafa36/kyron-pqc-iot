#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pqc_device.h"
#include "pqc_test_wrapper.h"

#define MSG "Hello Kyron! This is a 2 Device Communication test"

typedef struct {
    uint8_t ascon_key[ASCON_KEY_BYTES];
    uint8_t nonce[ASCON_NONCE_BYTES];
    uint8_t ct_buf[PQC_MAX_BUFFER];
    unsigned long long ct_len;
    uint8_t recv_buf[PQC_MAX_BUFFER];
    size_t decrypted_len;
    uint8_t sig_buf[PQC_MAX_BUFFER];
    size_t sig_len;
} Device;

int main(void) {
    int ret;

    printf("=== PQC Multi-Device In-Memory Test ===\n");

    Device sender, receiver;

    // -------- Step 0: Initialize session (shared key) --------
    printf("[Session] Generating shared ASCON key...\n");
    ret = pqc_init_wrapper();   // wrapper generates internal key
    if (ret != 0) {
        printf("[ERROR] Wrapper init failed\n");
        return 1;
    }

    memcpy(sender.ascon_key, pqc_dilithium_get_pk(), ASCON_KEY_BYTES); // simulate session
    memcpy(receiver.ascon_key, sender.ascon_key, ASCON_KEY_BYTES);

    // -------- Step 1: Sender generates Dilithium keypair --------
    printf("[Sender] Generating Dilithium keypair...\n");
    ret = pqc_dilithium_keypair();
    if (ret != 0) { printf("[ERROR] Keypair generation failed\n"); return 1; }
    printf("[OK] Keypair generated\n");

    // -------- Step 2: Sender signs message --------
    printf("[Sender] Signing message: \"%s\"\n", MSG);
    ret = pqc_dilithium_sign((const uint8_t *)MSG, strlen(MSG));
    if (ret != 0) { printf("[ERROR] Signing failed\n"); return 1; }
    sender.sig_len = pqc_dilithium_get_siglen();
    memcpy(sender.sig_buf, pqc_dilithium_get_sig(), sender.sig_len);
    printf("[OK] Message signed (sig_len = %zu bytes)\n", sender.sig_len);

    // -------- Step 3: Sender encrypts message + signature --------
    printf("[Sender] Encrypting message + signature...\n");
    ret = pqc_ascon_encrypt_full_message(
        sender.ct_buf,
        &sender.ct_len,
        (const uint8_t *)MSG, strlen(MSG),
        sender.sig_buf,
        sender.sig_len,
        sender.nonce,
        sender.ascon_key
    );
    if (ret != 0) { printf("[ERROR] Encryption failed\n"); return 1; }
    printf("[OK] Encryption done, nonce generated\n");

    // -------- Step 4: Receiver decrypts --------
    printf("[Receiver] Decrypting received message...\n");
    unsigned long long decrypted_len = 0;
    ret = pqc_ascon_decrypt_full_message(
        receiver.recv_buf,
        &decrypted_len,
        receiver.sig_buf,
        sender.sig_len,
        sender.ct_buf,
        sender.ct_len,
        sender.nonce,
        receiver.ascon_key
    );
    if (ret != 0) { printf("[ERROR] Decryption failed\n"); return 1; }

    receiver.decrypted_len = (size_t)decrypted_len;
    receiver.sig_len = sender.sig_len;
    printf("[OK] Decryption successful, message length = %zu\n", receiver.decrypted_len);

    // -------- Step 5: Verify message --------
    if (receiver.decrypted_len != strlen(MSG) ||
        memcmp(receiver.recv_buf, MSG, strlen(MSG)) != 0) {
        printf("[ERROR] Message mismatch!\n");
        return 1;
    }
    printf("[OK] Decrypted message matches original\n");

    // -------- Step 6: Verify signature --------
    ret = pqc_dilithium_verify(receiver.recv_buf, receiver.decrypted_len);
    if (ret != 0) {
        printf("[ERROR] Signature verification failed\n");
        return 1;
    }
    printf("[OK] Signature verified successfully\n");

    printf("=== Multi-Device In-Memory Test Passed ===\n");
    return 0;
}

