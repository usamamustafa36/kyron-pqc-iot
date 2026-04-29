#ifndef ASCON_API_H
#define ASCON_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_KEY_BYTES 16
#define ASCON_NONCE_BYTES 16
#define ASCON_TAG_BYTES 16
#define ASCON_MAX_PLAINTEXT_BYTES 256
#define ASCON_MAX_CIPHERTEXT_BYTES (ASCON_MAX_PLAINTEXT_BYTES + ASCON_TAG_BYTES)

/* Stream context: holds key, base nonce, counter, aggregate tag and last chunk tag.
 * Kept in header so callers can allocate the context on stack/flash easily. */
typedef struct {
    uint8_t key[ASCON_KEY_BYTES];
    uint8_t base_nonce[ASCON_NONCE_BYTES];
    uint64_t counter;
    uint8_t last_chunk_tag[ASCON_TAG_BYTES];
    uint8_t aggregate_tag[ASCON_TAG_BYTES];
    int is_encrypt; /* 1 = encrypt, 0 = decrypt */
} ascon_stream_ctx_t;

/* One-shot AEAD API */
int ascon_encrypt(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                  const uint8_t *plaintext, unsigned long long plaintext_len,
                  const uint8_t *associated_data, unsigned long long ad_len,
                  const uint8_t *nonce, const uint8_t *key);

int ascon_decrypt(uint8_t *plaintext, unsigned long long *plaintext_len,
                  const uint8_t *ciphertext, unsigned long long ciphertext_len,
                  const uint8_t *associated_data, unsigned long long ad_len,
                  const uint8_t *nonce, const uint8_t *key);

int ascon_encrypt_with_nonce_generation(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                                       const uint8_t *plaintext, unsigned long long plaintext_len,
                                       const uint8_t *associated_data, unsigned long long ad_len,
                                       uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *key);

/* Hash wrapper: requires that you compile with -DHAVE_ASCON_HASH and link
 * an implementation of:
 *   int ascon_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
 * The wrapper returns 0 on success.
 */
int ascon_hash_wrapper(uint8_t *hash_out, size_t hash_out_len,
                       const uint8_t *input, size_t input_len);

/* Streaming API prototypes */
int ascon_stream_init(ascon_stream_ctx_t *ctx, const uint8_t *key,
                      const uint8_t *base_nonce, int is_encrypt);

int ascon_stream_update_encrypt(ascon_stream_ctx_t *ctx,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t *associated_data, size_t ad_len,
                                uint8_t *ciphertext, unsigned long long *ciphertext_len);

int ascon_stream_update_decrypt(ascon_stream_ctx_t *ctx,
                                uint8_t *plaintext, unsigned long long *plaintext_len,
                                const uint8_t *ciphertext, unsigned long long ciphertext_len,
                                const uint8_t *associated_data, size_t ad_len);

/* Finalize: outputs the aggregated tag into out_tag (size >= ASCON_TAG_BYTES).
 * This function does NOT zero the aggregate_tag so callers can verify it after finalize.
 */
int ascon_stream_finalize(ascon_stream_ctx_t *ctx, uint8_t *out_tag, size_t out_tag_len);

/* Wipe and cleanup stream context memory (zeroes all sensitive fields). */
void ascon_stream_ctx_cleanup(ascon_stream_ctx_t *ctx);

/* Verify the aggregated stream tag in constant time against expected_tag.
 * Returns 0 if match, -1 if mismatch or error.
 */
int ascon_stream_verify(const ascon_stream_ctx_t *ctx, const uint8_t *expected_tag, size_t expected_len);

#ifdef __cplusplus
}
#endif

#endif /* ASCON_API_H */

