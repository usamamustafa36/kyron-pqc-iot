#include "pqc_test_wrapper.h"
#include "randombytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define MAX_MSG_LEN 1024
#define MAX_SIGNATURE DILITHIUM_SIGNATURE_BYTES
#define MAX_CIPHERTEXT PQC_MAX_BUFFER

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); return 1;
    }
    printf("Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);

    pqc_init_wrapper();

    // --- Kyber key exchange ---
    uint8_t server_kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t client_kyber_pk[KYBER_PUBLIC_KEY_BYTES], client_kyber_sk[KYBER_SECRET_KEY_BYTES];
    pqc_kyber_keypair(client_kyber_pk, client_kyber_sk);

    if (read(sockfd, server_kyber_pk, KYBER_PUBLIC_KEY_BYTES) <= 0) { perror("read"); return 1; }

    uint8_t client_ct[KYBER_CIPHERTEXT_BYTES], session_key[ASCON_KEY_BYTES];
    pqc_kyber_encapsulate(client_ct, session_key, server_kyber_pk);
    write(sockfd, client_ct, KYBER_CIPHERTEXT_BYTES);
    printf("Secure session established.\n");

    // --- Dilithium key exchange ---
    pqc_dilithium_keypair();
    write(sockfd, pqc_dilithium_get_pk(), DILITHIUM_PUBLIC_KEY_BYTES);

    uint8_t server_dilithium_pk[DILITHIUM_PUBLIC_KEY_BYTES];
    if (read(sockfd, server_dilithium_pk, DILITHIUM_PUBLIC_KEY_BYTES) <= 0) { perror("read"); return 1; }

    // --- Chat loop ---
    fd_set read_fds;
    char input[MAX_MSG_LEN];

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sockfd, &read_fds);
        int maxfd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;

        if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) < 0) { perror("select"); break; }

        // Send
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

            write(sockfd, nonce, ASCON_NONCE_BYTES);
            write(sockfd, &sig_len, sizeof(size_t));
            write(sockfd, &ct_len, sizeof(unsigned long long));
            write(sockfd, ct_buf, ct_len);
        }

        // Receive
        if (FD_ISSET(sockfd, &read_fds)) {
            uint8_t nonce[ASCON_NONCE_BYTES];
            size_t sig_len;
            unsigned long long ct_len;
            uint8_t ct_buf[MAX_CIPHERTEXT];

            if (read(sockfd, nonce, ASCON_NONCE_BYTES) <= 0) break;
            if (read(sockfd, &sig_len, sizeof(size_t)) <= 0) break;
            if (read(sockfd, &ct_len, sizeof(unsigned long long)) <= 0) break;
            if (ct_len > MAX_CIPHERTEXT) { printf("[!] Message too big\n"); break; }
            if (read(sockfd, ct_buf, ct_len) <= 0) break;

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
                                   server_dilithium_pk) != 0) {
                printf("[!] Message signature invalid!\n");
            } else {
                printf("[Server]: %.*s\n", (int)dec_len, decrypted);
            }
        }
    }

    close(sockfd);
    return 0;
}

