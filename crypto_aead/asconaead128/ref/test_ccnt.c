#include <stdio.h>
#include <stdint.h>

static inline uint32_t read_ccnt(void) {
    uint32_t cc;
    asm volatile ("mrc p15, 0, %0, c9, c13, 0" : "=r"(cc));
    return cc;
}

int main() {
    uint32_t cc = read_ccnt();
    printf("Cycle count: %u\n", cc);
    return 0;
}
