#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT 5000

int main() {
    int server_fd, c1, c2;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 2);

    printf("[SERVER] Waiting for Client A...\n");
    c1 = accept(server_fd, (struct sockaddr*)&addr, &addr_len);
    printf("[SERVER] Client A connected.\n");

    printf("[SERVER] Waiting for Client B...\n");
    c2 = accept(server_fd, (struct sockaddr*)&addr, &addr_len);
    printf("[SERVER] Client B connected.\n\n");
    printf("[SERVER] Chat relay running (encrypted messages only).\n");

    fd_set set;
    int maxfd = (c1 > c2 ? c1 : c2) + 1;
    uint8_t buf[2048];
    int len;

    while (1) {
        FD_ZERO(&set);
        FD_SET(c1, &set);
        FD_SET(c2, &set);

        select(maxfd, &set, NULL, NULL, NULL);

        if (FD_ISSET(c1, &set)) {
            len = read(c1, buf, sizeof(buf));
            if (len <= 0) break;
            write(c2, buf, len);
        }

        if (FD_ISSET(c2, &set)) {
            len = read(c2, buf, sizeof(buf));
            if (len <= 0) break;
            write(c1, buf, len);
        }
    }

    close(c1);
    close(c2);
    close(server_fd);
    return 0;
}
