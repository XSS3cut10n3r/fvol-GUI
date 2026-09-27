/* Shared helpers for the reference harnesses in bench/refbench/ (C and C++):
 * monotonic clock, mmap of a window of a (multi-GB) memory image, case file reading.
 * Nothing here copies the image into memory: the window is mmapped read-only and every
 * engine scans the mapping in place (exactly what the rust drivers in
 * src/yara/benchdrv.rs do), so all engines see the same bytes at the same addresses.
 */
#ifndef FASTVOL_BENCHUTIL_H
#define FASTVOL_BENCHUTIL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* memmem */
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static inline double bu_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Parse "123", "0x40000000", "256M", "1G" (binary suffixes). */
static inline size_t bu_size(const char *s) {
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end && *end) {
        switch (*end) {
        case 'k': case 'K': v <<= 10; break;
        case 'm': case 'M': v <<= 20; break;
        case 'g': case 'G': v <<= 30; break;
        default: break;
        }
    }
    return (size_t)v;
}

/* mmap [off, off+len) of `path` read-only (off must be page aligned); *len is clamped
 * to the file size. The first touch of every page happens in bu_warm(). */
static inline const unsigned char *bu_map_window(const char *path, size_t off, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        exit(2);
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || (size_t)st.st_size <= off) {
        fprintf(stderr, "bad window offset\n");
        exit(2);
    }
    if (off + *len > (size_t)st.st_size) *len = (size_t)st.st_size - off;
    void *p = mmap(NULL, *len, PROT_READ, MAP_SHARED, fd, (off_t)off);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap: %s\n", strerror(errno));
        exit(2);
    }
    close(fd);
    madvise(p, *len, MADV_WILLNEED);
    return (const unsigned char *)p;
}

/* Fault every page in once so the first measured engine is not charged for page cache /
 * page table population (all measurements are best-of-N anyway). */
static inline unsigned bu_warm(const unsigned char *p, size_t len) {
    volatile unsigned acc = 0;
    for (size_t i = 0; i < len; i += 4096) acc += p[i];
    return acc;
}

/* Read a whole (small) text file; NUL terminated. */
static inline char *bu_read_file(const char *path, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "read %s failed\n", path);
        exit(2);
    }
    buf[n] = 0;
    fclose(f);
    if (outlen) *outlen = (size_t)n;
    return buf;
}

/* Iterate the "name<TAB>pattern" lines of regex_cases.tsv (skips blank and # lines).
 * Returns the number of cases; names/pats/lens point into `buf` (modified in place). */
#define BU_MAX_CASES 256
static inline int bu_parse_cases(char *buf, char **names, char **pats, size_t *lens) {
    int n = 0;
    char *line = buf;
    while (line && *line && n < BU_MAX_CASES) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\r') line[--ll] = 0;
        char *tab = strchr(line, '\t');
        if (ll && line[0] != '#' && tab) {
            *tab = 0;
            names[n] = line;
            pats[n] = tab + 1;
            lens[n] = strlen(tab + 1);
            n++;
        }
        line = nl ? nl + 1 : NULL;
    }
    return n;
}

/* Is `name` in the comma separated list `sel` (NULL / empty = everything)? */
static inline int bu_selected(const char *sel, const char *name) {
    if (!sel || !*sel) return 1;
    size_t n = strlen(name);
    for (const char *p = sel; *p;) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && !memcmp(p, name, n)) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

#endif
