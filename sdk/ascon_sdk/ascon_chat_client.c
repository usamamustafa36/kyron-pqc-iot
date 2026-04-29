#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ascon_api.h"  // Your ASCON API

#define PORT 5000

int main() {
    int sock;
    struct sockaddr_in server;
    fd_set set;

    uint8_t key[16] = {0};
    uint8_t nonce[16] = {1};
    uint8_t ad[] = "CHAT";

    uint8_t plaintext[1024];
    uint8_t ciphertext[2048];
    uint8_t decrypted[1024];

    unsigned long long clen, dlen;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

    connect(sock, (struct sockaddr*)&server, sizeof(server));
    printf("[CLIENT] Connected to server.\n");
    printf("Type messages and press ENTER to send.\n\n");

    while (1) {
        FD_ZERO(&set);
        FD_SET(0, &set);
        FD_SET(sock, &set);

        select(sock + 1, &set, NULL, NULL, NULL);

        // Input from keyboard
        if (FD_ISSET(0, &set)) {
            fgets((char*)plaintext, sizeof(plaintext), stdin);

            clen = sizeof(ciphertext);
            ascon_encrypt(ciphertext, &clen,
                          plaintext, strlen((char*)plaintext),
                          ad, strlen((char*)ad),
                          nonce, key);

            write(sock, ciphertext, clen);
        }

        // Incoming encrypted message
        if (FD_ISSET(sock, &set)) {
            int len = read(sock, ciphertext, sizeof(ciphertext));
            if (len <= 0) break;

            dlen = sizeof(decrypted);
            if (ascon_decrypt(decrypted, &dlen,
                              ciphertext, len,
                              ad, strlen((char*)ad),
                              nonce, key) == 0)
            {
                decrypted[dlen] = 0;
                printf("\n[New Message]: %s", decrypted);
            }
        }
    }

    close(sock);
    return 0;
}
