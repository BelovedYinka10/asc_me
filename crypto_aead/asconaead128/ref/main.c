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
#include <malloc.h>

#include "api.h"
#include "crypto_aead.h"

#define NUM_ITERATIONS 1.0  // Simulating real-device behavior (1 message at a time)

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

double time_diff_ns(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
}

void print_memory_usage(const char *label) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0 || strncmp(line, "VmSize:", 7) == 0) {
            printf("[%s] %s", label, line);
        }
    }
    fclose(fp);
}

int main() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    uint8_t key[CRYPTO_KEYBYTES] = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";

    size_t msg_len = 800 * 1024;  // 800 KB
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
    print_memory_usage("Before Encryption");

    clock_gettime(CLOCK_MONOTONIC, &start_enc);
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    unsigned long long clen = 0;
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    clock_gettime(CLOCK_MONOTONIC, &end_enc);
    print_memory_usage("After Encryption");
    getrusage(RUSAGE_SELF, &enc_usage_after);

    uint64_t enc_cycles = 0;
    read(fd, &enc_cycles, sizeof(enc_cycles));
    close(fd);

    double enc_time_ms = time_diff_ns(start_enc, end_enc) / 1e6;
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
    print_memory_usage("Before Decryption");

    clock_gettime(CLOCK_MONOTONIC, &start_dec);
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    unsigned long long mlen = 0;
    crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    clock_gettime(CLOCK_MONOTONIC, &end_dec);
    print_memory_usage("After Decryption");
    getrusage(RUSAGE_SELF, &dec_usage_after);

    uint64_t dec_cycles = 0;
    read(fd, &dec_cycles, sizeof(dec_cycles));
    close(fd);

    double dec_time_ms = time_diff_ns(start_dec, end_dec) / 1e6;
    long dec_mem_used_kb = dec_usage_after.ru_maxrss - dec_usage_before.ru_maxrss;

    // === Check if decryption was successful
    int match = memcmp(msg, decrypted, msg_len);
    printf("\n✅ Decryption match: %s\n", (match == 0) ? "YES" : "❌ NO");

    // === Output
    printf("\n=== ENCRYPTION RESULTS ===\n");
    printf("Time taken: %.3f ms\n", enc_time_ms);
    printf("CPU cycles: %lu\n", enc_cycles);
    printf("Memory usage delta: %ld KB\n", enc_mem_used_kb);
    printf("Ciphertext length: %llu bytes\n", clen);

    printf("\n=== DECRYPTION RESULTS ===\n");
    printf("Time taken: %.3f ms\n", dec_time_ms);
    printf("CPU cycles: %lu\n", dec_cycles);
    printf("Memory usage delta: %ld KB\n", dec_mem_used_kb);
    printf("Decrypted length: %llu bytes\n", mlen);

    printf("\n=== MALLOC ALLOCATIONS ===\n");
    printf("msg buffer       : %zu bytes\n", msg_mem);
    printf("ciphertext buffer: %zu bytes\n", ct_mem);
    printf("decrypted buffer : %zu bytes\n", dec_mem);
    printf("Total malloc     : %.2f KB\n", (msg_mem + ct_mem + dec_mem) / 1024.0);

    free(msg);
    free(ct);
    free(decrypted);
    return 0;
}
