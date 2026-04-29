#include "pqc_test_wrapper.h"
#include "randombytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define PORT 8081
#define MAX_MSG_LEN 1024
#define MAX_SIGNATURE DILITHIUM_SIGNATURE_BYTES
#define MAX_CIPHERTEXT PQC_MAX_BUFFER

int main() {
    int sockfd, newsockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen = sizeof(cli_addr);

    // --- 1. Setup socket ---
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { perror("bind"); return 1; }
    listen(sockfd, 1);
    printf("Server listening on port %d...\n", PORT);

    newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
    if (newsockfd < 0) { perror("accept"); return 1; }
    printf("Client connected.\n");

    // --- 2. Initialize PQC ---
    pqc_init_wrapper();

    // --- 3. Kyber key exchange ---
    uint8_t server_kyber_pk[KYBER_PUBLIC_KEY_BYTES], server_kyber_sk[KYBER_SECRET_KEY_BYTES];
    pqc_kyber_keypair(server_kyber_pk, server_kyber_sk);
    write(newsockfd, server_kyber_pk, KYBER_PUBLIC_KEY_BYTES);

    uint8_t client_ct[KYBER_CIPHERTEXT_BYTES];
    if (read(newsockfd, client_ct, KYBER_CIPHERTEXT_BYTES) <= 0) {
        printf("[!] Failed to read client ciphertext\n");
        close(newsockfd); close(sockfd); return 1;
    }

    uint8_t session_key[ASCON_KEY_BYTES];
    pqc_kyber_decapsulate(session_key, client_ct, server_kyber_sk);
    printf("Secure session established.\n");

    // --- 4. Dilithium key exchange ---
    pqc_dilithium_keypair();
    write(newsockfd, pqc_dilithium_get_pk(), DILITHIUM_PUBLIC_KEY_BYTES);

    uint8_t client_dilithium_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    if (read(newsockfd, client_dilithium_pk, DILITHIUM_PUBLIC_KEY_BYTES) <= 0) {
        printf("[!] Failed to read client Dilithium PK\n");
        close(newsockfd); close(sockfd); return 1;
    }

    // --- 5. Real-time chat loop ---
    fd_set read_fds;
    char input[MAX_MSG_LEN];

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(newsockfd, &read_fds);
        int maxfd = (newsockfd > STDIN_FILENO) ? newsockfd : STDIN_FILENO;

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

            uint8_t nonce[ASCON_NONCE_BYTES];
            randombytes(nonce, ASCON_NONCE_BYTES);

            uint8_t ct_buf[MAX_CIPHERTEXT];
            unsigned long long ct_len = 0;
            pqc_ascon_encrypt_full_message(ct_buf, &ct_len,
                                           (uint8_t*)input, msg_len,
                                           signature, sig_len,
                                           nonce, session_key);

            write(newsockfd, nonce, ASCON_NONCE_BYTES);
            write(newsockfd, &sig_len, sizeof(size_t));
            write(newsockfd, &ct_len, sizeof(unsigned long long));
            write(newsockfd, ct_buf, ct_len);
        }

        // --- Receive message ---
        if (FD_ISSET(newsockfd, &read_fds)) {
            uint8_t nonce[ASCON_NONCE_BYTES];
            size_t sig_len;
            unsigned long long ct_len;
            uint8_t ct_buf[MAX_CIPHERTEXT];

            if (read(newsockfd, nonce, ASCON_NONCE_BYTES) <= 0) break;
            if (read(newsockfd, &sig_len, sizeof(size_t)) <= 0) break;
            if (read(newsockfd, &ct_len, sizeof(unsigned long long)) <= 0) break;
            if (ct_len > MAX_CIPHERTEXT) { printf("[!] Message too big\n"); break; }
            if (read(newsockfd, ct_buf, ct_len) <= 0) break;

            uint8_t decrypted[MAX_MSG_LEN];
            uint8_t signature[MAX_SIGNATURE];
            unsigned long long dec_len = 0;

            if (pqc_ascon_decrypt_full_message(decrypted, &dec_len,
                                               signature, sig_len,
                                               ct_buf, ct_len,
                                               nonce, session_key) != 0) {
                printf("[!] Failed to decrypt message\n");
                continue;
            }

            if (pqc_verify_message(decrypted, dec_len, signature, sig_len,
                                   client_dilithium_pk) != 0) {
                printf("[!] Message signature invalid!\n");
            } else {
                printf("[Client]: %.*s\n", (int)dec_len, decrypted);
            }
        }
    }

    close(newsockfd);
    close(sockfd);
    return 0;
}

