#include <stdio.h>
#include <string.h>
#include <unistd.h>     // for sleep()
#include "kyber_api.h"

int main() {
    unsigned char pk[KYBER_PUBLIC_KEY_BYTES];
    unsigned char sk[KYBER_SECRET_KEY_BYTES];
    unsigned char ct[KYBER_CIPHERTEXT_BYTES];
    unsigned char ss_enc[KYBER_SHARED_SECRET_BYTES];
    unsigned char ss_dec[KYBER_SHARED_SECRET_BYTES];

    const char *session_id = "TEST_SESSION_001";
    int expiry_minutes = 1;  // 1 minute for testing auto-expiry

    printf("=== Running Kyber512 Functional & DB Test ===\n");

    // 1️⃣ Initialize DB
    kyber_db_init();

    // 2️⃣ Generate keypair with session + store in DB
    if (kyber_generate_keypair_with_session(session_id, pk, sk, expiry_minutes) != 0) {
        printf("Keygen FAILED\n");
        return 1;
    }
    printf("Keypair generated and stored in DB for session '%s'\n", session_id);

    // 3️⃣ Display masked keys
    printf("\nMasked Keys After Generation:\n");
    kyber_get_visible_keys();

    // 4️⃣ Test crypto operations
    if (kyber_encapsulate(ct, ss_enc, pk) != 0) {
        printf("Encapsulation FAILED\n");
        return 1;
    }

    if (kyber_decapsulate(ss_dec, ct, sk) != 0) {
        printf("Decapsulation FAILED\n");
        return 1;
    }

    if (memcmp(ss_enc, ss_dec, KYBER_SHARED_SECRET_BYTES) == 0) {
        printf("\nSUCCESS ✓ — Shared secrets match!\n");
    } else {
        printf("\nFAILED ✗ — Shared secrets mismatch!\n");
        printf("Encapsulated SS: ");
        for(int i=0;i<KYBER_SHARED_SECRET_BYTES;i++) printf("%02x", ss_enc[i]); 
        printf("\nDecapsulated SS: ");
        for(int i=0;i<KYBER_SHARED_SECRET_BYTES;i++) printf("%02x", ss_dec[i]); 
        printf("\n");
        return 1;
    }

    // 5️⃣ Wait for key to expire and auto-cleanup
    printf("\nWaiting 65 seconds to test auto-expiry...\n");
    sleep(65);
    kyber_cleanup_expired_keys();

    printf("\nMasked Keys After Auto-Expiry Cleanup:\n");
    kyber_get_visible_keys();

    // 6️⃣ Re-create session for deletion test
    kyber_generate_keypair_with_session(session_id, pk, sk, expiry_minutes);
    printf("\nKeys recreated for session deletion test:\n");
    kyber_get_visible_keys();

    // 7️⃣ Delete session manually
    kyber_delete_session(session_id);
    printf("\nAfter manual deletion of session '%s':\n", session_id);
    kyber_get_visible_keys();

    return 0;
}

