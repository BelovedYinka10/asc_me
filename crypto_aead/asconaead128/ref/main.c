// ascon_bench.c — ASCON AEAD table: Avg Time, Avg Cycles, Avg Stack (no heap)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>

#include "api.h"
#include "crypto_aead.h"

#ifndef NUM_ITERATIONS
#define NUM_ITERATIONS 1000
#endif

// ---------- timing ----------
static inline double time_diff_ns(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1e9 + (e.tv_nsec - s.tv_nsec);
}

// ---------- perf_event_open wrapper ----------
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// ---------- optional: pin to CPU 0 ----------
static void pin_to_cpu0(void) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    (void)sched_setaffinity(0, sizeof(mask), &mask);
}

// ---------- STACK usage (KB) ----------
static long current_stack_kb(void) {
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return -1;

    void *stack_base = NULL; // lowest address
    size_t stack_size = 0;
    int r = pthread_attr_getstack(&attr, &stack_base, &stack_size);
    pthread_attr_destroy(&attr);
    if (r != 0 || !stack_base || stack_size == 0) return -1;

    volatile int marker = 0;
    void *sp = (void *)&marker;

    char *low  = (char *)stack_base;
    char *high = low + stack_size; // typical upper bound for downward-growing stacks
    char *csp  = (char *)sp;

    long used_bytes;
    if (csp <= high && csp >= low) {
        used_bytes = (long)(high - csp); // downward growth
    } else {
        long d1 = (long)llabs((long)(csp - low));
        long d2 = (long)llabs((long)(high - csp));
        used_bytes = d1 < d2 ? d1 : d2;
    }
    if (used_bytes < 0) used_bytes = 0;
    return used_bytes / 1024; // KB
}

int main(void) {
    pin_to_cpu0();

    // ---- test data
    const size_t msg_len = 800 * 1024; // 800 KB payload
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    uint8_t *ct  = (uint8_t *)malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *pt  = (uint8_t *)malloc(msg_len + CRYPTO_ABYTES);
    if (!msg || !ct || !pt) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i & 0xFF);

    uint8_t key[CRYPTO_KEYBYTES]   = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES]= {0};
    uint8_t ad[] = "MacBook";
    unsigned long long clen = 0, mlen = 0;

    // ---- perf setup (cycles)
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int perf_ok = 1;
    int fd_probe = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd_probe == -1) {
        perf_ok = 0;
        fprintf(stderr,
                "Warning: perf_event_open failed (%s). Cycles will be shown as N/A.\n"
                "Hint: sudo sh -c 'echo 1 > /proc/sys/kernel/perf_event_paranoid'\n",
                strerror(errno));
    } else {
        close(fd_probe);
    }

    // ---- warm-up
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
    crypto_aead_decrypt(pt, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

    // ---- metrics accumulators
    double total_time_enc_ms = 0.0, total_time_dec_ms = 0.0;
    unsigned long long total_cycles_enc = 0ULL, total_cycles_dec = 0ULL;
    long total_stack_enc_kb = 0, total_stack_dec_kb = 0;

    // ---- ENCRYPT loop
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        int fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        struct timespec s, e;
        clock_gettime(CLOCK_MONOTONIC, &s);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &e);

        unsigned long long cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }

        total_time_enc_ms += time_diff_ns(s, e) / 1e6;
        total_cycles_enc  += cycles;

        long stk = current_stack_kb();
        if (stk > 0) total_stack_enc_kb += stk;
    }

    // ---- DECRYPT loop
    for (int i = 0; i < NUM_ITERATIONS; ++i) {
        int fd = -1;
        if (perf_ok) {
            fd = perf_event_open(&pe, 0, 0, -1, 0);
            if (fd == -1) perf_ok = 0;
        }

        struct timespec s, e;
        clock_gettime(CLOCK_MONOTONIC, &s);
        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }

        crypto_aead_decrypt(pt, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

        if (perf_ok) { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
        clock_gettime(CLOCK_MONOTONIC, &e);

        unsigned long long cycles = 0ULL;
        if (perf_ok) {
            if (read(fd, &cycles, sizeof(cycles)) != (ssize_t)sizeof(cycles)) cycles = 0ULL;
            close(fd);
        }

        total_time_dec_ms += time_diff_ns(s, e) / 1e6;
        total_cycles_dec  += cycles;

        long stk = current_stack_kb();
        if (stk > 0) total_stack_dec_kb += stk;
    }

    // ---- correctness
    int ok = (mlen == msg_len) && (memcmp(msg, pt, msg_len) == 0);

    // ---- averages
    const double iters = (double)NUM_ITERATIONS;
    double avg_time_enc_ms = total_time_enc_ms / iters;
    double avg_time_dec_ms = total_time_dec_ms / iters;
    double avg_cycles_enc  = perf_ok ? (double)total_cycles_enc / iters : 0.0;
    double avg_cycles_dec  = perf_ok ? (double)total_cycles_dec / iters : 0.0;
    double avg_stack_enc_kb = (double)total_stack_enc_kb / iters;
    double avg_stack_dec_kb = (double)total_stack_dec_kb / iters;

    // ---- table output (like your Kyber table; no heap)
    printf("\n| Operation | Avg Time (ms) | Avg Cycles | Avg Stack (KB) |\n");
    printf("|-----------|---------------:|-----------:|----------------:|\n");
    if (perf_ok) {
        printf("| Encrypt   | %13.3f | %11.0f | %14.2f |\n",
               avg_time_enc_ms, avg_cycles_enc, avg_stack_enc_kb);
        printf("| Decrypt   | %13.3f | %11.0f | %14.2f |\n",
               avg_time_dec_ms, avg_cycles_dec, avg_stack_dec_kb);
    } else {
        printf("| Encrypt   | %13.3f | %11s | %14.2f |\n",
               avg_time_enc_ms, "N/A", avg_stack_enc_kb);
        printf("| Decrypt   | %13.3f | %11s | %14.2f |\n",
               avg_time_dec_ms, "N/A", avg_stack_dec_kb);
    }

    printf("\nDecryption match: %s\n", ok ? "YES" : "NO");

    free(msg);
    free(ct);
    free(pt);
    return ok ? 0 : 1;
}
