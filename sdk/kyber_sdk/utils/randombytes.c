#include "randombytes.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
  #include <windows.h>
  #include <wincrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/types.h>
  #if defined(__linux__)
    #include <sys/random.h>
  #endif
#else
  #error "Unsupported platform for randombytes"
#endif

static void randombytes_core(uint8_t *buf, size_t len) {
#if defined(_WIN32)
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "Windows RNG init failed\n");
        abort();
    }
    if (!CryptGenRandom(hProvider, (DWORD)len, buf)) {
        fprintf(stderr, "Windows RNG failed\n");
        CryptReleaseContext(hProvider, 0);
        abort();
    }
    CryptReleaseContext(hProvider, 0);

#elif defined(__linux__)
    ssize_t ret = getrandom(buf, len, 0);
    if (ret < 0) {
        // fallback to /dev/urandom
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) { perror("open /dev/urandom"); abort(); }
        size_t got = 0;
        while (got < len) {
            ssize_t r = read(fd, buf + got, len - got);
            if (r <= 0) { perror("read /dev/urandom"); abort(); }
            got += (size_t)r;
        }
        close(fd);
    }

#elif defined(__APPLE__) || defined(__unix__)
    // macOS, BSD: use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); abort(); }
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, buf + got, len - got);
        if (r <= 0) { perror("read /dev/urandom"); abort(); }
        got += (size_t)r;
    }
    close(fd);

#else
    #error "No RNG implementation available for this platform"
#endif
}

// Main API
void randombytes(uint8_t *buf, size_t len) {
    randombytes_core(buf, len);
}

// PQClean aliases
void PQCLEAN_randombytes(uint8_t *buf, size_t len) {
    randombytes_core(buf, len);
}

void PQCLEAN_MLKEM512_CLEAN_randombytes(uint8_t *buf, size_t len) {
    randombytes_core(buf, len);
}

void PQCLEAN_MLDSA44_CLEAN_randombytes(uint8_t *buf, size_t len) {
    randombytes_core(buf, len);
}

