#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <errno.h>

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    // Use CPU 0 explicitly
    int fd = perf_event_open(&pe, 0, 0, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // === Workload being measured ===
    volatile uint64_t sum = 0;
    for (uint64_t i = 0; i < 1000000; ++i) {
        sum += i;
    }
    // ==============================

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t count = 0;
    if (read(fd, &count, sizeof(count)) == -1) {
        perror("read");
        close(fd);
        return 1;
    }

    printf("CPU cycles used: %lu\n", count);
    close(fd);
    return 0;
}
