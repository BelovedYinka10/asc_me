// ascon_bench_rss.c — ASCON AEAD: Avg Time, Avg Cycles, Avg RSS (KB) + Peak VmHWM
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

#include "api.h"
#include "crypto_aead.h"

#ifndef NUM_ITERATIONS
#define NUM_ITERATIONS 1000
#endif

// ---- timing
static inline double time_diff_ns(struct timespec s, struct timespec e) {
    return (e.tv_sec - s.tv_sec) * 1e9 + (e.tv_nsec - s.tv_nsec);
}

// ---- perf_event_open
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// ---- pin to CPU0 (optional)
static void pin_to_cpu0(void) {
    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(0, &mask);
    (void)sched_setaffinity(0, sizeof(mask), &mask);
}

// ---- /proc/self/status helpers (KB)
static long read_status_kb(const char *key) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256]; long val = -1; size_t k = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, k) == 0) {
            if (sscanf(line + k, " %ld", &val) == 1) break;
        }
    }
    fclose(f);
    return val;
}
static long current_rss_kb(void) { return read_status_kb("VmRSS:"); }
static long peak_hwm_kb(void)    { return read_status_kb("VmHWM:"); }

int main(void) {
    pin_to_cpu0();

    // Test payload (same as your previous: 800 KB)
    const size_t msg_len = 800 * 1024;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    uint8_t *ct  = (uint8_t *)malloc(msg_len + CRYPTO_ABYTES);
    uint8_t *pt  = (uint8_t *)malloc(msg_len + CRYPTO_ABYTES);
    if (!msg || !ct || !pt) { fprintf(stderr, "malloc failed\n"); return 1; }
    for (size_t i = 0; i < msg_len; i++) msg[i] = (uint8_t)(i & 0xFF);

    uint8_t key[CRYPTO_KEYBYTES]    = {0};
    uint8_t nonce[CRYPTO_NPUBBYTES] = {0};
    uint8_t ad[] = "MacBook";
    unsigned long long clen = 0, mlen = 0;

    // perf setup (cycles)
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
            "Warning: perf_event_open failed (%s). Cycles will be N/A.\n"
            "Hint: sudo sh -c 'echo 1 > /proc/sys/kernel/perf_event_paranoid'\n",
            strerror(errno));
    } else {
        close(fd_probe);
    }

    // Warm-up (avoid cold caches)
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
    crypto_aead_decrypt(pt, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);

    // Accumulators
    double total_time_enc_ms = 0.0, total_time_dec_ms = 0.0;
    unsigned long long total_cycles_enc = 0ULL, total_cycles_dec = 0ULL;
    long total_rss_enc_kb = 0, total_rss_dec_kb = 0;
    long peak_seen_kb = peak_hwm_kb();

    // Encrypt loop
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

        long rss = current_rss_kb(); if (rss > 0) total_rss_enc_kb += rss;
        long hwm = peak_hwm_kb();    if (hwm > peak_seen_kb) peak_seen_kb = hwm;
    }

    // Decrypt loop
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

        long rss = current_rss_kb(); if (rss > 0) total_rss_dec_kb += rss;
        long hwm = peak_hwm_kb();    if (hwm > peak_seen_kb) peak_seen_kb = hwm;
    }

    // Correctness
    int ok = (mlen == msg_len) && (memcmp(msg, pt, msg_len) == 0);

    // Averages
    const double iters = (double)NUM_ITERATIONS;
    double avg_time_enc_ms = total_time_enc_ms / iters;
    double avg_time_dec_ms = total_time_dec_ms / iters;
    double avg_cycles_enc  = perf_ok ? (double)total_cycles_enc / iters : 0.0;
    double avg_cycles_dec  = perf_ok ? (double)total_cycles_dec / iters : 0.0;
    double avg_rss_enc_kb  = (double)total_rss_enc_kb / iters;
    double avg_rss_dec_kb  = (double)total_rss_dec_kb / iters;

    // Table
    printf("\n| Operation | Avg Time (ms) | Avg Cycles | Avg RSS (KB) |\n");
    printf("|-----------|---------------:|-----------:|-------------:|\n");
    if (perf_ok) {
        printf("| Encrypt   | %13.3f | %11.0f | %12.2f |\n",
               avg_time_enc_ms, avg_cycles_enc, avg_rss_enc_kb);
        printf("| Decrypt   | %13.3f | %11.0f | %12.2f |\n",
               avg_time_dec_ms, avg_cycles_dec, avg_rss_dec_kb);
    } else {
        printf("| Encrypt   | %13.3f | %11s | %12.2f |\n",
               avg_time_enc_ms, "N/A", avg_rss_enc_kb);
        printf("| Decrypt   | %13.3f | %11s | %12.2f |\n",
               avg_time_dec_ms, "N/A", avg_rss_dec_kb);
    }

    printf("\nPeak VmHWM: %ld KB\n", peak_seen_kb);
    printf("Decryption match: %s\n", ok ? "YES" : "NO");

    free(msg); free(ct); free(pt);
    return ok ? 0 : 1;
}
