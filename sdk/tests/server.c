#include "pqc_test_wrapper.h"
#include "randombytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define PORT 8080
#define MAX_MSG_LEN 16384
#define MAX_SIGNATURE 512
#define MAX_CLIENTS 2

typedef struct {
    int fd;
    uint8_t session_key[ASCON_KEY_BYTES];
    uint8_t dilithium_pk[DILITHIUM_PUBLIC_KEY_BYTES];
} client_t;

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;
    socklen_t clilen = sizeof(struct sockaddr_in);
    client_t clients[MAX_CLIENTS] = {0};

    // --- 1. Setup server socket ---
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { perror("bind"); return 1; }
    listen(sockfd, MAX_CLIENTS);
    printf("[SERVER] Listening on port %d...\n", PORT);

    // --- 2. Initialize PQC wrapper ---
    pqc_init_wrapper();
    printf("[PQC] Wrapper initialized.\n");

    fd_set master_set, read_fds;
    FD_ZERO(&master_set);
    FD_SET(sockfd, &master_set);
    int maxfd = sockfd;

    while (1) {
        read_fds = master_set;
        if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) < 0) { perror("select"); break; }

        for (int fd = 0; fd <= maxfd; fd++) {
            if (!FD_ISSET(fd, &read_fds)) continue;

            // --- New client connection ---
            if (fd == sockfd) {
                struct sockaddr_in cli_addr;
                int newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
                if (newsockfd < 0) { perror("accept"); continue; }

                int slot = -1;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].fd == 0) { slot = i; break; }
                }
                if (slot == -1) { printf("[SERVER] Max clients reached!\n"); close(newsockfd); continue; }

                clients[slot].fd = newsockfd;
                FD_SET(newsockfd, &master_set);
                if (newsockfd > maxfd) maxfd = newsockfd;

                printf("[SERVER] New client connected: slot=%d fd=%d\n", slot, newsockfd);

                // --- Kyber key exchange ---
                uint8_t server_kyber_pk[KYBER_PUBLIC_KEY_BYTES], server_kyber_sk[KYBER_SECRET_KEY_BYTES];
                pqc_kyber_keypair(server_kyber_pk, server_kyber_sk);

                printf("[PQC] Kyber PK[0..7]: ");
                for(int i=0;i<8;i++) printf("%02X ", server_kyber_pk[i]); printf("\n");

                write(newsockfd, server_kyber_pk, KYBER_PUBLIC_KEY_BYTES);

                uint8_t client_ct[KYBER_CIPHERTEXT_BYTES];
                read(newsockfd, client_ct, KYBER_CIPHERTEXT_BYTES);

                pqc_kyber_decapsulate(clients[slot].session_key, client_ct, server_kyber_sk);
                printf("[PQC] Session key for client %d: ", slot);
                for(int i=0;i<8;i++) printf("%02X ", clients[slot].session_key[i]); printf("\n");

                // --- Dilithium key exchange ---
                pqc_dilithium_keypair();
                write(newsockfd, pqc_dilithium_get_pk(), DILITHIUM_PUBLIC_KEY_BYTES);
                read(newsockfd, clients[slot].dilithium_pk, DILITHIUM_PUBLIC_KEY_BYTES);
                printf("[PQC] Dilithium PK stored for client %d: ", slot);
                for(int i=0;i<8;i++) printf("%02X ", clients[slot].dilithium_pk[i]); printf("\n");
            }

            // --- Existing client message ---
            else {
                uint8_t nonce[ASCON_NONCE_BYTES];
                unsigned long long ct_len;
                size_t sig_len;
                uint8_t ct_buf[PQC_MAX_BUFFER];

                int r = read(fd, nonce, ASCON_NONCE_BYTES);
                if (r <= 0) { close(fd); FD_CLR(fd, &master_set); for(int i=0;i<MAX_CLIENTS;i++){ if(clients[i].fd==fd) clients[i].fd=0; } continue; }

                read(fd, &sig_len, sizeof(sig_len));
                read(fd, &ct_len, sizeof(ct_len));
                if (ct_len > PQC_MAX_BUFFER) { printf("[!] Ciphertext too large\n"); continue; }
                read(fd, ct_buf, ct_len);

                client_t *sender = NULL;
                for(int i=0;i<MAX_CLIENTS;i++){ if(clients[i].fd==fd){ sender=&clients[i]; break; } }
                if(!sender) continue;

                uint8_t decrypted[MAX_MSG_LEN];
                uint8_t signature[MAX_SIGNATURE];
                unsigned long long dec_len=0;

                if(pqc_ascon_decrypt_full_message(decrypted, &dec_len, signature, sig_len, ct_buf, ct_len, nonce, sender->session_key)!=0){
                    printf("[!] Failed to decrypt message\n"); continue;
                }

                if(pqc_verify_message(decrypted, dec_len, signature, sig_len, sender->dilithium_pk)!=0){
                    printf("[!] Message signature invalid!\n"); continue;
                }

                printf("[Client %d]: %.*s\n", fd, (int)dec_len, decrypted);

                // --- Relay to other clients ---
                for(int i=0;i<MAX_CLIENTS;i++){
                    if(clients[i].fd!=0 && clients[i].fd!=fd){
                        uint8_t relay_nonce[ASCON_NONCE_BYTES];
                        randombytes(relay_nonce, ASCON_NONCE_BYTES);
                        uint8_t relay_ct[PQC_MAX_BUFFER];
                        unsigned long long relay_len=0;

                        pqc_ascon_encrypt_full_message(relay_ct, &relay_len, decrypted, dec_len, signature, sig_len, relay_nonce, clients[i].session_key);

                        write(clients[i].fd, relay_nonce, ASCON_NONCE_BYTES);
                        write(clients[i].fd, &sig_len, sizeof(sig_len));
                        write(clients[i].fd, &relay_len, sizeof(relay_len));
                        write(clients[i].fd, relay_ct, relay_len);
                    }
                }
            }
        }
    }

    close(sockfd);
    return 0;
}

