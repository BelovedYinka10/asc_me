#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "api.h"
#include "crypto_aead.h"

// Try hardware counters first
#if defined(__arm__) || defined(__aarch64__)
#define TRY_HW_COUNTERS 1
#else
#define TRY_HW_COUNTERS 0
#endif

// Performance counter state
static int fddev = -1;
static int hw_counters_available = 0;
static double cpu_hz = 1.0e9; // Default to 1GHz if detection fails

// Initialize performance monitoring
void init_perf() {
    #if TRY_HW_COUNTERS
    struct perf_event_attr pe = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1
    };

    fddev = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    hw_counters_available = (fddev != -1);
    #endif

    // Get CPU frequency as fallback
    FILE* f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (f) {
        unsigned long freq_khz;
        if (fscanf(f, "%lu", &freq_khz) == 1) {
            cpu_hz = freq_khz * 1000.0;
        }
        fclose(f);
    }
}

// Get current time in nanoseconds
uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Measure operation
void measure_operation(const char* name, void (*op)(void)) {
    uint64_t cycles = 0;
    uint64_t time_ns = 0;

    if (hw_counters_available) {
        ioctl(fddev, PERF_EVENT_IOC_RESET, 0);
        ioctl(fddev, PERF_EVENT_IOC_ENABLE, 0);
        op();
        ioctl(fddev, PERF_EVENT_IOC_DISABLE, 0);
        read(fddev, &cycles, sizeof(cycles));
    } else {
        uint64_t start = get_time_ns();
        op();
        time_ns = get_time_ns() - start;
        cycles = (uint64_t)(time_ns * (cpu_hz / 1e9));
    }

    if (hw_counters_available) {
        printf("%s cycles: %lu\n", name, cycles);
    } else {
        printf("%s time: %.3f ms (estimated cycles: %lu)\n",
               name, time_ns/1e6, cycles);
    }
}

// Wrapper functions for crypto operations
void encrypt_wrapper() {
    unsigned long long clen;
    crypto_aead_encrypt(ct, &clen, msg, msg_len, ad, sizeof(ad), NULL, nonce, key);
}

void decrypt_wrapper() {
    unsigned long long mlen;
    crypto_aead_decrypt(decrypted, &mlen, NULL, ct, clen, ad, sizeof(ad), nonce, key);
}

int main() {
    // ... (same initialization code as before) ...

    init_perf();

    // --- ENCRYPTION ---
    measure_operation("Encryption", encrypt_wrapper);
    printf("Ciphertext length: %llu bytes\n", clen);

    // --- DECRYPTION ---
    measure_operation("Decryption", decrypt_wrapper);
    printf("Decrypted message length: %llu bytes\n", mlen);

    // ... (cleanup code as before) ...
    return 0;
}