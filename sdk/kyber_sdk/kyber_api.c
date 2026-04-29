#include "kyber_api.h"
#include "PQCLEAN_MLKEM512_CLEAN_api.h"
#include "randombytes.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DB_PATH "keys.db"
#define PK_LEN PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SK_LEN PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES

// ------------------ DB INIT ------------------
void kyber_db_init() {
    sqlite3 *db; char *err = NULL;
    sqlite3_open(DB_PATH, &db);

    const char *query =
        "CREATE TABLE IF NOT EXISTS kyber_sessions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "session_id TEXT UNIQUE NOT NULL,"
        "pk BLOB NOT NULL,"
        "sk BLOB NOT NULL,"
        "created_at INTEGER NOT NULL,"
        "expiry INTEGER NOT NULL"
        ");";

    sqlite3_exec(db, query, 0, 0, &err);
    sqlite3_close(db);
}

// ------------------ STORE KEY WITH SESSION + METADATA ------------------
static void store_key_in_db(const char *session_id, uint8_t *pk, uint8_t *sk, int validity_minutes) {
    sqlite3 *db; sqlite3_open(DB_PATH, &db);

    time_t now = time(NULL);
    time_t exp = (validity_minutes > 0) ? now + (validity_minutes * 60) : 0;

    const char *sql = "INSERT INTO kyber_sessions (session_id, pk, sk, created_at, expiry) VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, pk, PK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, sk, SK_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, now);
    sqlite3_bind_int64(stmt, 5, exp);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// ------------------ AUTO EXPIRY CLEANER ------------------
int kyber_cleanup_expired_keys() {
    sqlite3 *db; sqlite3_open(DB_PATH, &db);

    time_t now = time(NULL);
    const char *sql = "DELETE FROM kyber_sessions WHERE expiry > 0 AND expiry <= ?";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int64(stmt, 1, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

// ------------------ REMOVE SPECIFIC SESSION ------------------
int kyber_delete_session(const char *session_id) {
    sqlite3 *db; sqlite3_open(DB_PATH, &db);

    const char *sql = "DELETE FROM kyber_sessions WHERE session_id = ?";
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

// ------------------ MASKED VIEW (for dashboard later) ------------------
int kyber_get_visible_keys() {
    sqlite3 *db; sqlite3_open(DB_PATH, &db);

    const char *sql = "SELECT session_id, pk, expiry FROM kyber_sessions";
    sqlite3_stmt *stmt; sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    printf("\n===== ACTIVE KYBER SESSIONS (Visibility Mode) =====\n");

    time_t now = time(NULL);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *sid = (const char*)sqlite3_column_text(stmt, 0);
        const uint8_t *pk = sqlite3_column_blob(stmt, 1);
        time_t exp = sqlite3_column_int64(stmt, 2);

        printf("Session: %s | Key: ", sid);

        for (int i = 0; i < 8; i++)   // visible prefix only
            printf("%02X", pk[i]);

        printf("******** | Expires in %llds\n", (long long)(exp - now));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

// ------------------ CORE CRYPTO API ------------------
// Generates session ID internally, expiry optional
int kyber_generate_keypair(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;

    char session_id[17]; // 16 random bytes + null terminator
    randombytes((uint8_t*)session_id, 16);
    session_id[16] = '\0';

    return kyber_generate_keypair_with_session(session_id, pk, sk, 0); // 0 = no auto-expiry
}

// Old API kept for backward compatibility
int kyber_generate_keypair_with_session(const char *session_id, uint8_t *pk, uint8_t *sk, int expiry_minutes) {
    if (!session_id || !pk || !sk) return -1;

    int res = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    if (res == 0) store_key_in_db(session_id, pk, sk, expiry_minutes);

    return res;
}

int kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    if (!ct || !ss || !pk) return -1;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    if (!ss || !ct || !sk) return -1;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}

