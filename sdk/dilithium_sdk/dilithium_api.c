// dilithium_api.c
#include "PQCLEAN_MLDSA44_CLEAN_api.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DB_PATH "dilithium_keys.db"

// Internal buffers for keys and signature
static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t sig[CRYPTO_BYTES];
static size_t siglen;

// ------------------ DB helpers ------------------
static int init_db() {
    sqlite3 *db;
    char *err = 0;
    int rc = sqlite3_open(DB_PATH, &db);
    if (rc != SQLITE_OK) return rc;

    const char *sql_create = "CREATE TABLE IF NOT EXISTS dilithium_keys ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                             "pk BLOB NOT NULL,"
                             "sk BLOB NOT NULL"
                             ");";
    rc = sqlite3_exec(db, sql_create, 0, 0, &err);
    if (rc != SQLITE_OK) sqlite3_free(err);

    sqlite3_close(db);
    return rc;
}

static int save_key_to_db() {
    sqlite3 *db;
    sqlite3_open(DB_PATH, &db);

    const char *sql_insert = "INSERT INTO dilithium_keys (pk, sk) VALUES (?, ?);";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql_insert, -1, &stmt, 0);
    sqlite3_bind_blob(stmt, 1, pk, CRYPTO_PUBLICKEYBYTES, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, sk, CRYPTO_SECRETKEYBYTES, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return (rc == SQLITE_DONE) ? 0 : rc;
}

int dilithium_load_key_for_session() {
    sqlite3 *db;
    sqlite3_open(DB_PATH, &db);

    const char *sql_select = "SELECT pk, sk FROM dilithium_keys ORDER BY id DESC LIMIT 1;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memcpy(pk, sqlite3_column_blob(stmt, 0), CRYPTO_PUBLICKEYBYTES);
        memcpy(sk, sqlite3_column_blob(stmt, 1), CRYPTO_SECRETKEYBYTES);
        rc = 0;
    } else rc = -1;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

int dilithium_clear_session(void) {
    sqlite3 *db;
    sqlite3_open(DB_PATH, &db);
    sqlite3_exec(db, "DELETE FROM dilithium_keys;", 0, 0, 0);
    sqlite3_close(db);

    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(sig, 0, sizeof(sig));
    siglen = 0;
    return 0;
}

// ------------------ SDK API ------------------
int dilithium_keygen(void) {
    init_db();
    int rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    if (rc != 0) return rc;
    return save_key_to_db();
}

int dilithium_sign(const uint8_t *msg, size_t mlen) {
    if (sk[0]==0) return -1; // make sure key loaded in session
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, &siglen, msg, mlen, sk);
}

// Verify using current session key (must load key first)
int dilithium_verify(const uint8_t *msg, size_t mlen) {
    if (pk[0]==0) return -1; // ensure session key is loaded
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, msg, mlen, pk);
}

// Stateless verification with arbitrary PK
int dilithium_verify_with_pk(const uint8_t *sig_in, size_t siglen_in,
                             const uint8_t *msg, size_t mlen, const uint8_t *pk_in) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig_in, siglen_in, msg, mlen, pk_in);
}

// ------------------ Getters ------------------
const uint8_t *dilithium_get_pk(void) { return pk; }
const uint8_t *dilithium_get_sk(void) { return sk; }
const uint8_t *dilithium_get_sig(void) { return sig; }
size_t         dilithium_get_siglen(void) { return siglen; }

