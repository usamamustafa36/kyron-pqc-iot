#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "ascon_api.h"
#include "ascon_hash.h"
#include "crypto_aead.h"
#include "randombytes.h"  // Provides randombytes() function

/* Require a real Ascon hash primitive: one-shot ascon_hash(out,outlen,in,inlen) */
#ifndef HAVE_ASCON_HASH
#include "ascon_hash.h"

#endif

/* If your crypto headers define these, they should match these values; but we
 * default the crypto constants to the ASCON_* macros from the header. */
#ifndef CRYPTO_NPUBBYTES
#define CRYPTO_NPUBBYTES ASCON_NONCE_BYTES
#endif
#ifndef CRYPTO_KEYBYTES
#define CRYPTO_KEYBYTES ASCON_KEY_BYTES
#endif
#ifndef CRYPTO_ABYTES
#define CRYPTO_ABYTES ASCON_TAG_BYTES
#endif

/* ---------- Forward: declare external ascon_hash provided by library ---------- */
/* Signature expected:
 * int ascon_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
 * The user must link this symbol into final program.
 */
extern int ascon_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* ---------- One-shot AEAD wrappers (FE-1) ---------- */
int ascon_encrypt(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                  const uint8_t *plaintext, unsigned long long plaintext_len,
                  const uint8_t *associated_data, unsigned long long ad_len,
                  const uint8_t *nonce, const uint8_t *key)
{
    if (!ciphertext || !ciphertext_len || !plaintext || !nonce || !key) {
        return -1;
    }
    return crypto_aead_encrypt(ciphertext, ciphertext_len,
                               plaintext, plaintext_len,
                               associated_data, ad_len,
                               NULL, nonce, key);
}

int ascon_decrypt(uint8_t *plaintext, unsigned long long *plaintext_len,
                  const uint8_t *ciphertext, unsigned long long ciphertext_len,
                  const uint8_t *associated_data, unsigned long long ad_len,
                  const uint8_t *nonce, const uint8_t *key)
{
    if (!plaintext || !plaintext_len || !ciphertext || !nonce || !key) {
        return -1;
    }
    return crypto_aead_decrypt(plaintext, plaintext_len,
                               NULL, ciphertext, ciphertext_len,
                               associated_data, ad_len,
                               nonce, key);
}

/* Helper: Generate nonce internally and call ascon_encrypt (FE-3 nonce mgmt) */
int ascon_encrypt_with_nonce_generation(uint8_t *ciphertext, unsigned long long *ciphertext_len,
                                       const uint8_t *plaintext, unsigned long long plaintext_len,
                                       const uint8_t *associated_data, unsigned long long ad_len,
                                       uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *key)
{
    if (nonce == NULL || nonce_len == 0 || !key) {
        return -1;  /* Invalid nonce buffer or key */
    }

    /* Fill nonce with secure random bytes */
    randombytes(nonce, nonce_len);

    return ascon_encrypt(ciphertext, ciphertext_len,
                         plaintext, plaintext_len,
                         associated_data, ad_len,
                         nonce, key);
}

/* ---------- Constant-time helpers & utilities (FE-3) ---------- */
static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0; /* 1 if equal, 0 otherwise */
}

/* Safer memory zeroization: attempt to prevent compiler optimizing it out. */
static void secure_zero(void *v, size_t n)
{
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) *p++ = 0;
}

/* ---------- Hash wrapper for firmware integrity (FE-2) ---------- */
/* Must call the linked ascon_hash() symbol. Returns 0 on success. */
int ascon_hash_wrapper(uint8_t *hash_out, size_t hash_out_len,
                       const uint8_t *input, size_t input_len)
{
    if (!hash_out || hash_out_len == 0 || (input_len && !input)) return -1;
    return ascon_hash(hash_out, hash_out_len, input, input_len);
}

/* ---------- Streaming / Chunked API (FE-5) ---------- */
int ascon_stream_init(ascon_stream_ctx_t *ctx, const uint8_t *key,
                      const uint8_t *base_nonce, int is_encrypt)
{
    if (!ctx || !key || !base_nonce) return -1;
    memcpy(ctx->key, key, CRYPTO_KEYBYTES);
    memcpy(ctx->base_nonce, base_nonce, CRYPTO_NPUBBYTES);
    ctx->counter = 0;
    memset(ctx->last_chunk_tag, 0, CRYPTO_ABYTES);
    /* Initialize aggregate_tag to a zero value; we will mix it with first chunk:
     * if using cryptographic hash mixing, we set aggregate_tag to all-zeros and
     * repeatedly compute aggregate = H(aggregate || chunk_tag). */
    memset(ctx->aggregate_tag, 0, CRYPTO_ABYTES);
    ctx->is_encrypt = is_encrypt ? 1 : 0;
    return 0;
}

static void derive_chunk_nonce(uint8_t *out_nonce, const uint8_t *base_nonce, uint64_t counter)
{
    size_t i;
    memcpy(out_nonce, base_nonce, CRYPTO_NPUBBYTES);
    for (i = 0; i < 8 && i < CRYPTO_NPUBBYTES; ++i) {
        out_nonce[CRYPTO_NPUBBYTES - 1 - i] ^= (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }
}

/* If HAVE_ASCON_HASH is defined (it must be), we accumulate an aggregated tag
 * via: aggregate = ascon_hash( aggregate || chunk_tag ). This approximates an
 * incremental hashing over tag sequence and yields a strong aggregated token.
 * (aggregate initially zeros). */
static int accumulate_tag_with_hash(uint8_t *agg, const uint8_t *tag)
{
    /* concat buffer: agg || tag */
    uint8_t buf[CRYPTO_ABYTES * 2];
    memcpy(buf, agg, CRYPTO_ABYTES);
    memcpy(buf + CRYPTO_ABYTES, tag, CRYPTO_ABYTES);
    /* compute new aggregate of size CRYPTO_ABYTES */
    return ascon_hash_wrapper(agg, CRYPTO_ABYTES, buf, sizeof(buf));
}

/* Fallback XOR accumulation is not used since HAVE_ASCON_HASH is required. */

int ascon_stream_update_encrypt(ascon_stream_ctx_t *ctx,
                                const uint8_t *plaintext, size_t plaintext_len,
                                const uint8_t *associated_data, size_t ad_len,
                                uint8_t *ciphertext, unsigned long long *ciphertext_len)
{
    uint8_t nonce[CRYPTO_NPUBBYTES];
    unsigned long long out_len = 0;
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) return -1;

    derive_chunk_nonce(nonce, ctx->base_nonce, ctx->counter);

    int rc = crypto_aead_encrypt(ciphertext, &out_len,
                                 plaintext, plaintext_len,
                                 associated_data, ad_len,
                                 NULL, nonce, ctx->key);
    if (rc != 0) return rc;

    if (out_len >= CRYPTO_ABYTES) {
        memcpy(ctx->last_chunk_tag, ciphertext + (out_len - CRYPTO_ABYTES), CRYPTO_ABYTES);
        /* update strong aggregate using hash */
        if (accumulate_tag_with_hash(ctx->aggregate_tag, ctx->last_chunk_tag) != 0) {
            return -1;
        }
    }

    ctx->counter += 1;
    *ciphertext_len = out_len;
    return 0;
}

int ascon_stream_update_decrypt(ascon_stream_ctx_t *ctx,
                                uint8_t *plaintext, unsigned long long *plaintext_len,
                                const uint8_t *ciphertext, unsigned long long ciphertext_len,
                                const uint8_t *associated_data, size_t ad_len)
{
    uint8_t nonce[CRYPTO_NPUBBYTES];
    if (!ctx || !plaintext || !plaintext_len || !ciphertext) return -1;

    derive_chunk_nonce(nonce, ctx->base_nonce, ctx->counter);

    int rc = crypto_aead_decrypt(plaintext, plaintext_len,
                                 NULL, ciphertext, ciphertext_len,
                                 associated_data, ad_len,
                                 nonce, ctx->key);
    if (rc != 0) return rc;

    if (ciphertext_len >= CRYPTO_ABYTES) {
        memcpy(ctx->last_chunk_tag, ciphertext + (ciphertext_len - CRYPTO_ABYTES), CRYPTO_ABYTES);
        /* update strong aggregate using hash */
        if (accumulate_tag_with_hash(ctx->aggregate_tag, ctx->last_chunk_tag) != 0) {
            return -1;
        }
    }

    ctx->counter += 1;
    return 0;
}

/* Finalize streaming: output the aggregated tag. We DO NOT zero aggregate_tag here
 * so the caller can call verify() afterwards. Callers MUST call ascon_stream_ctx_cleanup()
 * when done to zero sensitive state. */
int ascon_stream_finalize(ascon_stream_ctx_t *ctx, uint8_t *out_tag, size_t out_tag_len)
{
    if (!ctx || !out_tag || out_tag_len < CRYPTO_ABYTES) return -1;
    memcpy(out_tag, ctx->aggregate_tag, CRYPTO_ABYTES);
    return 0;
}

void ascon_stream_ctx_cleanup(ascon_stream_ctx_t *ctx)
{
    if (!ctx) return;
    secure_zero(ctx->key, sizeof(ctx->key));
    secure_zero(ctx->base_nonce, sizeof(ctx->base_nonce));
    secure_zero(ctx->last_chunk_tag, sizeof(ctx->last_chunk_tag));
    secure_zero(ctx->aggregate_tag, sizeof(ctx->aggregate_tag));
    secure_zero(&ctx->counter, sizeof(ctx->counter));
    ctx->is_encrypt = 0;
}

/* Verify aggregated tag in constant time. Returns 0 on match, -1 on mismatch. */
int ascon_stream_verify(const ascon_stream_ctx_t *ctx, const uint8_t *expected_tag, size_t expected_len)
{
    if (!ctx || !expected_tag || expected_len < CRYPTO_ABYTES) return -1;
    /* Compare ctx->aggregate_tag with expected_tag in constant time. */
    uint8_t local_agg[CRYPTO_ABYTES];
    memcpy(local_agg, ctx->aggregate_tag, CRYPTO_ABYTES);
    if (constant_time_compare(local_agg, expected_tag, CRYPTO_ABYTES)) {
        return 0;
    }
    return -1;
}

/* ---------- End of API ---------- */

