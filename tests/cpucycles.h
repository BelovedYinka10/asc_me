#ifndef CPUCYCLES_H_
#define CPUCYCLES_H_

#include <stdint.h>

static inline void cpucycles_init(void) {
    // Enable user access to performance counters
    uint32_t value = 1;
    __asm__ volatile("mcr p15, 0, %0, c9, c14, 0" : : "r"(value));

    // Reset performance counters
    value = 0x23;
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(value));

    // Enable cycle counter
    value = 0x8000000f;
    __asm__ volatile("mcr p15, 0, %0, c9, c12, 1" : : "r"(value));
}

static inline void cpucycles(uint32_t *cycles) {
    __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(*cycles));
}

#define cpucycles_reset() cpucycles_sum = 0
#define cpucycles_start() cpucycles(&cpucycles_before)
#define cpucycles_stop()                              \
    do {                                               \
        cpucycles(&cpucycles_after);                   \
        cpucycles_sum += cpucycles_after - cpucycles_before; \
    } while (0)
#define cpucycles_result() ((unsigned long long)cpucycles_sum)

static uint32_t cpucycles_before = 0;
static uint32_t cpucycles_after = 0;
static uint32_t cpucycles_sum = 0;

#endif  // CPUCYCLES_H_
