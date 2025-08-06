#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include <sched.h>
#include <malloc.h>  // for malloc_usable_size
#include "api.h"
#include "crypto_aead.h"

#define NUM_ITERATIONS 1000.0

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

double time_diff_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

int main() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

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

    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i % 256);

    size_t msg_mem = malloc_usable_size(msg);
    size_t ct_mem = malloc_usable_size(ct);
    size_t dec_mem = malloc_usable_size(decrypted);

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    // === ENCRYPTION ===
    int fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (encrypt)");
        return 1;
    }

    struct timespec start_enc, end_enc;
    struct rusage enc_usage_before, enc_usage_after;

    getrusage(RUSAGE_SELF, &enc_usage_before);
    clock_gettime(CLOCK_MONOTONIC, &start_enc);
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    volatile unsigned long long volatile_clen = 0;
    for (int i = 0; i < (int)NUM_ITERATIONS; ++i) {
        crypto_aead_encrypt(ct, (unsigned long long*)&volatile_clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    clock_gettime(CLOCK_MONOTONIC, &end_enc);
    getrusage(RUSAGE_SELF, &enc_usage_after);

    uint64_t total_enc_cycles = 0;
    read(fd, &total_enc_cycles, sizeof(total_enc_cycles));
    close(fd);

    double avg_enc_cycles = total_enc_cycles / NUM_ITERATIONS;
    double total_enc_time_ns = time_diff_ns(start_enc, end_enc);
    double avg_enc_time_ms = (total_enc_time_ns / 1e6) / NUM_ITERATIONS;
    long enc_mem_used_kb = enc_usage_after.ru_maxrss - enc_usage_before.ru_maxrss;

    // === DECRYPTION ===
    fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open (decrypt)");
        return 1;
    }

    struct timespec start_dec, end_dec;
    struct rusage dec_usage_before, dec_usage_after;

    getrusage(RUSAGE_SELF, &dec_usage_before);
    clock_gettime(CLOCK_MONOTONIC, &start_dec);
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    volatile unsigned long long volatile_mlen = 0;
    for (int i = 0; i < (int)NUM_ITERATIONS; ++i) {
        crypto_aead_decrypt(decrypted, (unsigned long long*)&volatile_mlen, NULL, ct, volatile_clen, ad, sizeof(ad), nonce, key);
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    clock_gettime(CLOCK_MONOTONIC, &end_dec);
    getrusage(RUSAGE_SELF, &dec_usage_after);

    uint64_t total_dec_cycles = 0;
    read(fd, &total_dec_cycles, sizeof(total_dec_cycles));
    close(fd);

    double avg_dec_cycles = total_dec_cycles / NUM_ITERATIONS;
    double total_dec_time_ns = time_diff_ns(start_dec, end_dec);
    double avg_dec_time_ms = (total_dec_time_ns / 1e6) / NUM_ITERATIONS;
    long dec_mem_used_kb = dec_usage_after.ru_maxrss - dec_usage_before.ru_maxrss;

    // === CHECKSUMS ===
    uint32_t ct_checksum = 0, pt_checksum = 0;
    for (size_t i = 0; i < volatile_clen; i++) ct_checksum += ct[i];
    for (size_t i = 0; i < volatile_mlen; i++) pt_checksum += decrypted[i];

    // === OUTPUT ===
    printf("\n=== ENCRYPTION RESULTS ===\n");
    printf("Average time per encryption: %.3f ms\n", avg_enc_time_ms);
    printf("Average cycles per encryption: %.2f\n", avg_enc_cycles);
    printf("Encryption memory usage (peak diff): %ld KB\n", enc_mem_used_kb);
    printf("Ciphertext checksum: %u\n", ct_checksum);
    printf("Ciphertext length: %llu bytes\n", volatile_clen);

    printf("\n=== DECRYPTION RESULTS ===\n");
    printf("Average time per decryption: %.3f ms\n", avg_dec_time_ms);
    printf("Average cycles per decryption: %.2f\n", avg_dec_cycles);
    printf("Decryption memory usage (peak diff): %ld KB\n", dec_mem_used_kb);
    printf("Decrypted checksum: %u\n", pt_checksum);
    printf("Decrypted length: %llu bytes\n", volatile_mlen);

    printf("\n=== BUFFER ALLOCATIONS (malloc_usable_size) ===\n");
    printf("msg buffer       : %zu bytes\n", msg_mem);
    printf("ciphertext buffer: %zu bytes\n", ct_mem);
    printf("decrypted buffer : %zu bytes\n", dec_mem);
    printf("Total allocated  : %zu bytes (%.2f KB)\n",
           msg_mem + ct_mem + dec_mem,
           (msg_mem + ct_mem + dec_mem) / 1024.0);

    free(msg);
    free(ct);
    free(decrypted);
    return 0;
}
