#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "api.h"
#include "crypto_aead.h"

// Performance counter setup
static int perf_fd = -1;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                          int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

void init_perf() {
    struct perf_event_attr pe = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1
    };

    perf_fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (perf_fd == -1) {
        fprintf(stderr, "Error opening performance counter. Running in timing mode.\n");
    }
}

uint64_t read_counter() {
    uint64_t count;
    if (read(perf_fd, &count, sizeof(count)) != sizeof(count)) {
        return 0;
    }
    return count;
}

void reset_counter() {
    if (perf_fd != -1) {
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    }
}

void start_counter() {
    if (perf_fd != -1) {
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    }
}

void stop_counter() {
    if (perf_fd != -1) {
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    }
}

int main() {
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);

    if (!msg || !ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    // Initialize message
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i % 256);
    }

    unsigned long long clen = 0, mlen = 0;
    uint64_t cycles;

    // Initialize performance counter
    init_perf();

    // --- ENCRYPTION ---
    reset_counter();
    start_counter();
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
    stop_counter();
    cycles = read_counter();

    printf("Encryption cycles: %lu\n", cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    // --- DECRYPTION ---
    reset_counter();
    start_counter();
    if (crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
        printf("Decryption failed!\n");
        free(msg);
        free(ct);
        free(decrypted);
        return 1;
    }
    stop_counter();
    cycles = read_counter();

    printf("Decryption cycles: %lu\n", cycles);
    printf("Decrypted message length: %llu bytes\n", mlen);

    free(msg);
    free(ct);
    free(decrypted);
    if (perf_fd != -1) close(perf_fd);
    return 0;
}