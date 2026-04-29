#ifndef KYBER_API_H
#define KYBER_API_H

#include <stdint.h>
#include "randombytes.h"   // your secure RNG function

#define KYBER_PUBLIC_KEY_BYTES 800
#define KYBER_SECRET_KEY_BYTES 1632
#define KYBER_CIPHERTEXT_BYTES 768
#define KYBER_SHARED_SECRET_BYTES 32

// ------------------ Core Crypto API ------------------

// New function: generates keypair with system-generated session ID (no expiry by default)
int kyber_generate_keypair(uint8_t *pk, uint8_t *sk);

// Original functions
int kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// ------------------ DB & Session Management ------------------

// Initialize SQLite DB (must call once at SDK startup)
void kyber_db_init(void);

// Generate keypair and store in DB linked to session ID, with expiry in minutes
int kyber_generate_keypair_with_session(const char *session_id,
                                        uint8_t *pk, uint8_t *sk,
                                        int expiry_minutes);

// Remove a session (delete key) manually
int kyber_delete_session(const char *session_id);

// Cleanup expired keys automatically
int kyber_cleanup_expired_keys(void);

// Masked key view for dashboard (first few bytes shown, rest masked)
int kyber_get_visible_keys(void);

#endif // KYBER_API_H

