#include "pqc_test_wrapper.h"
#include "randombytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define MAX_MSG_LEN 16384
#define MAX_SIGNATURE 512

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;

    // --- 1. Setup socket ---
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton"); return 1;
    }

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); return 1;
    }
    printf("[CLIENT] Connected to server %s:%d\n", SERVER_IP, PORT);

    // --- 2. Initialize PQC wrapper ---
    pqc_init_wrapper();
    printf("[PQC] Wrapper initialized.\n");

    // --- 3. Kyber key exchange ---
    uint8_t server_kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t client_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t session_key[ASCON_KEY_BYTES];

    // Receive server PK
    if (read(sockfd, server_kyber_pk, KYBER_PUBLIC_KEY_BYTES) != KYBER_PUBLIC_KEY_BYTES) {
        perror("[!] Failed to read server Kyber PK"); return 1;
    }
    printf("[PQC] Received server Kyber PK[0..7]: ");
    for(int i=0;i<8;i++) printf("%02X ", server_kyber_pk[i]); printf("\n");

    // Encapsulate session key
    if (pqc_kyber_encapsulate(client_ct, session_key, server_kyber_pk) != 0) {
        printf("[!] Failed to encapsulate session key\n"); return 1;
    }

    // Send ciphertext to server
    if (write(sockfd, client_ct, KYBER_CIPHERTEXT_BYTES) != KYBER_CIPHERTEXT_BYTES) {
        perror("[!] Failed to send Kyber ciphertext"); return 1;
    }
    printf("[PQC] Session key established. Key[0..7]: ");
    for(int i=0;i<8;i++) printf("%02X ", session_key[i]); printf("\n");

    // --- 4. Dilithium key exchange ---
    pqc_dilithium_keypair();
    uint8_t *client_dilithium_pk = pqc_dilithium_get_pk();
    if (write(sockfd, client_dilithium_pk, DILITHIUM_PUBLIC_KEY_BYTES) != DILITHIUM_PUBLIC_KEY_BYTES) {
        perror("[!] Failed to send Dilithium PK"); return 1;
    }
    printf("[PQC] Sent client Dilithium PK[0..7]: ");
    for(int i=0;i<8;i++) printf("%02X ", client_dilithium_pk[i]); printf("\n");

    uint8_t server_dilithium_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    if (read(sockfd, server_dilithium_pk, DILITHIUM_PUBLIC_KEY_BYTES) != DILITHIUM_PUBLIC_KEY_BYTES) {
        perror("[!] Failed to read server Dilithium PK"); return 1;
    }
    printf("[PQC] Received server Dilithium PK[0..7]: ");
    for(int i=0;i<8;i++) printf("%02X ", server_dilithium_pk[i]); printf("\n");

    // --- 5. Chat loop ---
    fd_set read_fds;
    char input[MAX_MSG_LEN];

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sockfd, &read_fds);
        int maxfd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;

        if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) < 0) { perror("select"); break; }

        // --- Send message ---
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (!fgets(input, MAX_MSG_LEN, stdin)) break;
            size_t msg_len = strlen(input);
            if (input[msg_len - 1] == '\n') input[msg_len - 1] = '\0';
            msg_len = strlen(input);

            uint8_t signature[MAX_SIGNATURE];
            size_t sig_len = 0;
            pqc_sign_message((uint8_t*)input, msg_len, signature, &sig_len);
            printf("[PQC] Message signed. Signature[0..7]: ");
            for(int i=0;i<8;i++) printf("%02X ", signature[i]); printf("\n");

            uint8_t nonce[ASCON_NONCE_BYTES];
            randombytes(nonce, ASCON_NONCE_BYTES);

            uint8_t ct_buf[PQC_MAX_BUFFER];
            unsigned long long ct_len = 0;
            pqc_ascon_encrypt_full_message(ct_buf, &ct_len, (uint8_t*)input, msg_len, signature, sig_len, nonce, session_key);
            printf("[PQC] Message encrypted. CT_len=%llu, CT[0..7]: ", ct_len);
            for(int i=0;i<8;i++) printf("%02X ", ct_buf[i]); printf("\n");

            write(sockfd, nonce, ASCON_NONCE_BYTES);
            write(sockfd, &sig_len, sizeof(sig_len));
            write(sockfd, &ct_len, sizeof(ct_len));
            write(sockfd, ct_buf, ct_len);
        }

        // --- Receive message ---
        if (FD_ISSET(sockfd, &read_fds)) {
            uint8_t nonce[ASCON_NONCE_BYTES];
            unsigned long long ct_len;
            size_t sig_len;
            uint8_t ct_buf[PQC_MAX_BUFFER];

            if (read(sockfd, nonce, ASCON_NONCE_BYTES) <= 0) break;
            if (read(sockfd, &sig_len, sizeof(sig_len)) <= 0) break;
            if (read(sockfd, &ct_len, sizeof(ct_len)) <= 0) break;
            if (ct_len > PQC_MAX_BUFFER) { printf("[!] Ciphertext too large\n"); continue; }
            if (read(sockfd, ct_buf, ct_len) <= 0) break;

            uint8_t decrypted[MAX_MSG_LEN];
            uint8_t signature[MAX_SIGNATURE];
            unsigned long long dec_len = 0;

            if (pqc_ascon_decrypt_full_message(decrypted, &dec_len, signature, sig_len, ct_buf, ct_len, nonce, session_key) != 0) {
                printf("[!] Failed to decrypt message\n"); continue;
            }

            if (pqc_verify_message(decrypted, dec_len, signature, sig_len, server_dilithium_pk) != 0)
                printf("[!] Message signature invalid!\n");
            else
                printf("[SERVER]: %.*s\n", (int)dec_len, decrypted);
        }
    }

    close(sockfd);
    return 0;
}

