/*
 * IP sampling profile of liblzma decoding a .xz file ("perf record" without perf), the C
 * counterpart of `codec_xz_micro profile`.
 *
 *   gcc -O2 -o codec_xz_prof codec_xz_prof.c -llzma
 *   codec_xz_prof EVENT PERIOD RUNS FILE   (EVENT: 0 cycles, 1 instructions, 5 branch misses)
 *
 * Prints "offset count" lines, hottest first, offsets relative to liblzma's load base
 * (objdump -d --start-address=... /usr/lib/liblzma.so.5 to annotate).
 */
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <lzma.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RING_PAGES (1 << 11)
#define HSIZE (1 << 20)
static uint64_t keys[HSIZE], counts[HSIZE];

static void add(uint64_t ip) {
    uint64_t h = (ip * 0x9E3779B97F4A7C15ull) >> 44;
    while (keys[h] && keys[h] != ip) h = (h + 1) & (HSIZE - 1);
    keys[h] = ip;
    counts[h]++;
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) exit(2);
    fclose(f);
    *len = n;
    return buf;
}

static int cmp(const void *a, const void *b) {
    uint64_t x = counts[*(const uint32_t *)a], y = counts[*(const uint32_t *)b];
    return x < y ? 1 : x > y ? -1 : 0;
}

/* codec_xz_prof events RUNS FILE CONFIG... : raw P-core event counts (hex PERF_TYPE_RAW configs)
 * of the run with the fewest cycles, like `codec_xz_micro events`. */
static int events(int argc, char **argv) {
    int runs = atoi(argv[2]);
    size_t in_len;
    unsigned char *in = read_file(argv[3], &in_len);
    int n = argc - 3;
    unsigned long long cfg[16] = {0x3c};
    for (int i = 1; i < n && i < 16; i++) cfg[i] = strtoull(argv[3 + i], 0, 16);
    int fds[16];
    for (int i = 0; i < n; i++) {
        struct perf_event_attr a;
        memset(&a, 0, sizeof a);
        a.type = PERF_TYPE_RAW;
        a.size = sizeof a;
        a.config = cfg[i];
        a.disabled = 1;
        a.exclude_kernel = 1;
        a.exclude_hv = 1;
        fds[i] = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
        if (fds[i] < 0) { perror("perf_event_open"); return 1; }
    }
    size_t cap = in_len * 64 + (1 << 20);
    unsigned long long best[16], v[16];
    best[0] = ~0ull;
    for (int r = 0; r < runs; r++) {
        unsigned char *out = malloc(cap);
        uint64_t memlimit = UINT64_MAX;
        size_t ip = 0, op = 0;
        for (int i = 0; i < n; i++) { ioctl(fds[i], PERF_EVENT_IOC_RESET, 0); ioctl(fds[i], PERF_EVENT_IOC_ENABLE, 0); }
        lzma_ret ret = lzma_stream_buffer_decode(&memlimit, 0, NULL, in, &ip, in_len, out, &op, cap);
        for (int i = 0; i < n; i++) {
            ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
            if (read(fds[i], &v[i], 8) != 8) v[i] = 0;
        }
        free(out);
        if (ret != LZMA_OK) { fprintf(stderr, "decode error %d\n", ret); return 1; }
        if (v[0] < best[0]) memcpy(best, v, sizeof v);
    }
    for (int i = 0; i < n; i++) printf("%#010llx %12llu %6.3f\n", cfg[i], best[i], (double)best[i] / best[0]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 3 && !strcmp(argv[1], "events")) return events(argc, argv);
    if (argc < 5) return 2;
    unsigned long long event = strtoull(argv[1], 0, 0), period = strtoull(argv[2], 0, 0);
    int runs = atoi(argv[3]);
    size_t in_len;
    unsigned char *in = read_file(argv[4], &in_len);
    unsigned long long pmu = 0;
    FILE *pf = fopen("/sys/bus/event_source/devices/cpu_core/type", "r");
    if (pf) { if (fscanf(pf, "%llu", &pmu) != 1) pmu = 0; fclose(pf); }
    int fd = -1;
    for (int precise = 2; precise >= 0 && fd < 0; precise--) {
        struct perf_event_attr a;
        memset(&a, 0, sizeof a);
        a.type = PERF_TYPE_HARDWARE;
        a.size = sizeof a;
        a.config = event | (pmu << 32);
        a.sample_period = period;
        a.sample_type = PERF_SAMPLE_IP;
        a.disabled = 1;
        a.exclude_kernel = 1;
        a.exclude_hv = 1;
        a.precise_ip = precise;
        fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    }
    if (fd < 0) { perror("perf_event_open"); return 1; }
    size_t rlen = (1 + RING_PAGES) * 4096;
    unsigned char *ring = mmap(0, rlen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    struct perf_event_mmap_page *mp = (void *)ring;
    unsigned char *data = ring + 4096;
    uint64_t size = RING_PAGES * 4096ull;
    size_t cap = in_len * 64 + (1 << 20);
    unsigned char *out = malloc(cap);
    for (int r = 0; r < runs; r++) {
        uint64_t memlimit = UINT64_MAX;
        size_t ip = 0, op = 0;
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        lzma_ret ret = lzma_stream_buffer_decode(&memlimit, 0, NULL, in, &ip, in_len, out, &op, cap);
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        if (ret != LZMA_OK) { fprintf(stderr, "decode error %d\n", ret); return 1; }
        uint64_t head = __atomic_load_n(&mp->data_head, __ATOMIC_ACQUIRE), tail = mp->data_tail;
        while (tail < head) {
            struct perf_event_header h;
            for (size_t i = 0; i < sizeof h; i++) ((unsigned char *)&h)[i] = data[(tail + i) % size];
            if (!h.size) break;
            if (h.type == PERF_RECORD_SAMPLE) {
                uint64_t v;
                for (size_t i = 0; i < 8; i++) ((unsigned char *)&v)[i] = data[(tail + 8 + i) % size];
                add(v);
            }
            tail += h.size;
        }
        __atomic_store_n(&mp->data_tail, head, __ATOMIC_RELEASE);
    }
    /* liblzma load base: lowest mapping of the library file */
    uint64_t base = UINT64_MAX;
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof line, m))
        if (strstr(line, "liblzma")) {
            uint64_t s = strtoull(line, 0, 16);
            if (s < base) base = s;
        }
    fclose(m);
    if (base == UINT64_MAX) { /* statically linked liblzma: offsets relative to the executable */
        char exe[512];
        ssize_t l = readlink("/proc/self/exe", exe, sizeof exe - 1);
        exe[l > 0 ? l : 0] = 0;
        m = fopen("/proc/self/maps", "r");
        while (fgets(line, sizeof line, m))
            if (l > 0 && strstr(line, exe)) {
                uint64_t s = strtoull(line, 0, 16);
                if (s < base) base = s;
            }
        fclose(m);
    }
    static uint32_t idx[HSIZE];
    uint32_t n = 0;
    for (uint32_t i = 0; i < HSIZE; i++)
        if (keys[i]) idx[n++] = i;
    qsort(idx, n, sizeof idx[0], cmp);
    for (uint32_t i = 0; i < n; i++) {
        uint64_t k = keys[idx[i]];
        if (k >= base && k - base < (1u << 30))
            printf("%llx %llu\n", (unsigned long long)(k - base), (unsigned long long)counts[idx[i]]);
        else
            printf("other:%llx %llu\n", (unsigned long long)k, (unsigned long long)counts[idx[i]]);
    }
    return 0;
}
