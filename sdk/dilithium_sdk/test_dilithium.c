// test_dilithium.c
#include <stdio.h>
#include <string.h>
#include "dilithium_api.h"

int main() {
    const char *message = "Hello, Dilithium!";
    size_t mlen = strlen(message);

    printf("=== Dilithium SDK Test ===\n");

    // 1. Generate keypair and store in DB
    if (dilithium_keygen() != 0) {
        printf("Key generation failed!\n");
        return 1;
    }
    printf("Keypair generated and saved to DB.\n");

    // 2. Sign the message
    if (dilithium_sign((const uint8_t*)message, mlen) != 0) {
        printf("Signing failed!\n");
        return 1;
    }
    printf("Message signed successfully.\n");

    // 3. Get signature info
    const uint8_t *sig = dilithium_get_sig();
    size_t siglen = dilithium_get_siglen();
    printf("Signature length: %zu bytes\n", siglen);

    // 4. Verify signature with stored public key
    if (dilithium_verify((const uint8_t*)message, mlen) == 0) {
        printf("Signature verified successfully with stored PK.\n");
    } else {
        printf("Signature verification failed!\n");
        return 1;
    }

    // 5. Verify signature with explicit PK
    const uint8_t *pk = dilithium_get_pk();
    if (dilithium_verify_with_pk(sig, siglen, (const uint8_t*)message, mlen, pk) == 0) {
        printf("Signature verified successfully with explicit PK.\n");
    } else {
        printf("Signature verification with explicit PK failed!\n");
        return 1;
    }

    // 6. Clear session keys
    if (dilithium_clear_session() == 0) {
        printf("Session cleared: keys deleted from DB and RAM.\n");
    } else {
        printf("Failed to clear session keys!\n");
    }

    printf("=== Dilithium SDK Test Complete ===\n");
    return 0;
}
