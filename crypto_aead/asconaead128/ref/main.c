#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include <sched.h> // For CPU affinity
#include "api.h"
#include "crypto_aead.h"

// Define a constant for the number of loop iterations
#define NUM_ITERATIONS 1000

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    // Pin the process to CPU 0 to ensure consistent measurements
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
        // We will continue anyway, but a warning is good
    }

    // Inputs
    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;
    uint8_t *msg = malloc(msg_len);
    uint8_t *ct = malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *decrypted = malloc(msg_len + CRYPTO_ABYTES);
    unsigned long long clen = 0, mlen = 0;

    if (!msg || !ct || !decrypted) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i % 256);

    // === ENCRYPTION Measurement ===
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (encrypt)");
        free(msg); free(ct); free(decrypted);
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // Use volatile to prevent compiler from optimizing the loop away
    volatile unsigned long long volatile_clen = 0;
    // Loop the encryption NUM_ITERATIONS times
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        crypto_aead_encrypt(ct, (unsigned long long*)&volatile_clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
        // This check forces the compiler to acknowledge the result of each call
        if (volatile_clen == 0) {
            // This is unlikely to happen, but it prevents the compiler from assuming
            // a single execution is enough.
            fprintf(stderr, "Encryption failed on iteration %d\n", i);
            break;
        }
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t total_enc_cycles = 0;
    if (read(fd, &total_enc_cycles, sizeof(total_enc_cycles)) != sizeof(total_enc_cycles)) {
        perror("read (encrypt)");
        close(fd);
        free(msg); free(ct); free(decrypted);
        return 1;
    }
    close(fd);

    // Store the last clen value for decryption and checksum
    clen = volatile_clen;

    uint64_t avg_enc_cycles = total_enc_cycles / NUM_ITERATIONS;

    // Prevent optimization
    __asm__ volatile("" : : "r"(clen), "r"(ct) : "memory");

    uint32_t ct_checksum = 0;
    for (size_t i = 0; i < clen; i++) ct_checksum += ct[i];

    printf("Ciphertext checksum: %u\n", ct_checksum);
    printf("Total Encryption cycles for %d iterations: %lu\n", NUM_ITERATIONS, total_enc_cycles);
    printf("Average Encryption cycles per operation: %lu\n", avg_enc_cycles);
    printf("Ciphertext length: %llu bytes\n", clen);

    // === DECRYPTION Measurement ===
    fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (decrypt)");
        free(msg); free(ct); free(decrypted);
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // Use volatile to prevent compiler from optimizing the loop away
    volatile unsigned long long volatile_mlen = 0;
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        crypto_aead_decrypt(decrypted, (unsigned long long*)&volatile_mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);
        // This check forces the compiler to acknowledge the result of each call
        if (volatile_mlen == 0) {
            fprintf(stderr, "Decryption failed on iteration %d\n", i);
            break;
        }
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t total_dec_cycles = 0;
    if (read(fd, &total_dec_cycles, sizeof(total_dec_cycles)) != sizeof(total_dec_cycles)) {
        perror("read (decrypt)");
        close(fd);
        free(msg); free(ct); free(decrypted);
        return 1;
    }
    close(fd);

    // Store the last mlen value
    mlen = volatile_mlen;

    uint64_t avg_dec_cycles = total_dec_cycles / NUM_ITERATIONS;

    __asm__ volatile("" : : "r"(mlen), "r"(decrypted) : "memory");

    uint32_t pt_checksum = 0;
    for (size_t i = 0; i < mlen; i++) pt_checksum += decrypted[i];

    printf("Decrypted checksum: %u\n", pt_checksum);
    printf("Total Decryption cycles for %d iterations: %lu\n", NUM_ITERATIONS, total_dec_cycles);
    printf("Average Decryption cycles per operation: %lu\n", avg_dec_cycles);
    printf("Decrypted message length: %llu bytes\n", mlen);

    free(msg);
    free(ct);
    free(decrypted);
    return 0;
}