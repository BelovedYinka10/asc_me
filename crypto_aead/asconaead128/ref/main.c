#define _POSIX_C_SOURCE 199309L  // For clock_gettime

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "api.h"
#include "crypto_aead.h"

// Helper to compute elapsed milliseconds
double elapsed_ms(struct timespec start, struct timespec end) {
    double sec = end.tv_sec - start.tv_sec;
    double nsec = end.tv_nsec - start.tv_nsec;
    return sec * 1000.0 + nsec / 1e6;
}

// Get resident memory (VmRSS) in KB on Linux
size_t getCurrentRSS() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    size_t rss = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            char* p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            rss = strtoul(p, NULL, 10);
            break;
        }
    }
    fclose(f);
    return rss;
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";
    printf("hi me")

    // Allocate 800 KB message and fill with random data
    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    if (!msg) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i % 256);
    }

    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);
    if (!ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        free(msg);
        return 1;
    }

    unsigned long long clen = 0, mlen = 0;
    struct timespec start, end;
    size_t mem_before, mem_after;

    // --- ENCRYPTION ---
    mem_before = getCurrentRSS();
    clock_gettime(CLOCK_MONOTONIC, &start);

    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);

    clock_gettime(CLOCK_MONOTONIC, &end);
    mem_after = getCurrentRSS();

    printf("Encryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Memory used during encryption: %zu KB\n", mem_after - mem_before);
    printf("Ciphertext length: %llu bytes\n", clen);

    // --- DECRYPTION ---
    mem_before = getCurrentRSS();
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        free(msg);
        free(ct);
        free(decrypted);
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    mem_after = getCurrentRSS();

    printf("Decryption time: %.3f ms\n", elapsed_ms(start, end));
    printf("Memory used during decryption: %zu KB\n", mem_after - mem_before);
    printf("Decrypted message length: %llu bytes\n", mlen);

    // Cleanup
    free(msg);
    free(ct);
    free(decrypted);

    return 0;
}
