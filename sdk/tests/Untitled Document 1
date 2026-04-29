#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "PQCLEAN_MLKEM512_CLEAN_api.h"    // Kyber macros
#include "PQCLEAN_MLDSA44_CLEAN_api.h"     // Dilithium macros
#include "crypto_aead.h"                   // Ascon encryption functions
#include "ascon_module.h"                  // Your Ascon wrapper functions

#define DILITHIUM_PUBKEY_SIZE (CRYPTO_PUBLICKEYBYTES + 64)
#define DILITHIUM_SECRETKEY_SIZE (CRYPTO_SECRETKEYBYTES + 64)
#define DILITHIUM_SIG_SIZE (CRYPTO_BYTES + 64)

#define ASCON_BUFFER_SIZE 3000   // Increased size to hold combined signature + message + overhead

int pqc_wrapper_run(void){
    // Kyber buffers - exact sizes from Kyber macros
    static uint8_t kyber_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    static uint8_t kyber_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    static uint8_t kyber_ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    static uint8_t kyber_ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    // Dilithium buffers with padding as recommended
    static uint8_t dil_pk[DILITHIUM_PUBKEY_SIZE];
    static uint8_t dil_sk[DILITHIUM_SECRETKEY_SIZE];
    static uint8_t dil_sig[DILITHIUM_SIG_SIZE];
    size_t siglen = 0;

    // Ascon buffers increased in size to avoid overflow
    static uint8_t ascon_key[16];
    static uint8_t ascon_nonce[16];
    static uint8_t ascon_ct[ASCON_BUFFER_SIZE];
    static uint8_t ascon_pt[ASCON_BUFFER_SIZE];

    // Combined buffer for signature + message
    static uint8_t combined[ASCON_BUFFER_SIZE];

    unsigned long long clen = 0, mlen = 0;

    const uint8_t message[] = "Kyron combined PQC message";

    printf("=== Kyber Key Exchange ===\n");
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kyber_pk, kyber_sk) != 0) {
        printf("❌ Kyber keypair failed!\n");
        return 1;
    }
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(kyber_ct, kyber_ss, kyber_pk) != 0) {
        printf("❌ Kyber encapsulation failed!\n");
        return 1;
    }
    uint8_t ss_dec[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    if (PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss_dec, kyber_ct, kyber_sk) != 0) {
        printf("❌ Kyber decapsulation failed!\n");
        return 1;
    }
    printf("%s Kyber shared secret matches!\n",
           memcmp(kyber_ss, ss_dec, sizeof(kyber_ss)) == 0 ? "✅" : "❌");

    printf("\n=== Dilithium Signing ===\n");
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(dil_pk, dil_sk) != 0) {
        printf("❌ Dilithium keypair failed!\n");
        return 1;
    }
    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(dil_sig, &siglen, message, sizeof(message), dil_sk) != 0) {
        printf("❌ Dilithium signing failed!\n");
        return 1;
    }
    printf("Dilithium signature length = %zu bytes\n", siglen);

    int valid = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(dil_sig, siglen, message, sizeof(message), dil_pk);
    printf("%s Dilithium signature verified!\n", valid == 0 ? "✅" : "❌");

    // Use Kyber shared secret as Ascon key and nonce (simple truncation or zero padding)
    memset(ascon_key, 0, sizeof(ascon_key));
    memset(ascon_nonce, 0, sizeof(ascon_nonce));
    memcpy(ascon_key, kyber_ss, sizeof(kyber_ss) < sizeof(ascon_key) ? sizeof(kyber_ss) : sizeof(ascon_key));
    memcpy(ascon_nonce, kyber_ss, sizeof(kyber_ss) < sizeof(ascon_nonce) ? sizeof(kyber_ss) : sizeof(ascon_nonce));

    ascon_init_key_nonce(ascon_key, ascon_nonce);

    printf("\n=== Ascon AEAD Encryption ===\n");
    size_t combined_len = siglen + sizeof(message);
    if (combined_len > sizeof(combined)) {
        printf("❌ Combined buffer too small!\n");
        return 1;
    }
    memcpy(combined, dil_sig, siglen);
    memcpy(combined + siglen, message, sizeof(message));

    if (ascon_encrypt_message(combined, combined_len, ascon_ct, &clen) != 0) {
        printf("❌ Ascon encryption failed!\n");
        return 1;
    }
    printf("Ascon ciphertext length = %llu bytes\n", clen);

    printf("\n=== Ascon AEAD Decryption ===\n");
    if (ascon_decrypt_message(ascon_ct, clen, ascon_pt, &mlen) != 0) {
        printf("❌ Ascon decryption failed!\n");
        return 1;
    }
    printf("Decrypted length = %llu bytes\n", mlen);

    if (mlen != combined_len || memcmp(ascon_pt, combined, combined_len) != 0) {
        printf("❌ Decrypted data mismatch!\n");
        return 1;
    } else {
        printf("✅ Ascon AEAD decrypted data matches original combined data!\n");
    }

    return 0;
}

