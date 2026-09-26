/*
 * Reference decompression throughput harness (liblzma, zlib, libbz2).
 *
 *   gcc -O3 -march=native -o refbench refbench.c -llzma -lz -lbz2
 *   refbench CODEC FILE RUNS [EXPECTED_OUTPUT_FILE]
 *
 * CODEC: xz | xz-mt | lzma | gzip | zlib | deflate | bz2
 *
 * The compressed file is loaded into memory once. Each timed run allocates a fresh output
 * buffer of the exact uncompressed size (like the Rust API, which returns a new Vec), decodes
 * the whole input in one call sequence, and frees the buffer outside the timed region.
 * Prints: "c <codec> <file> <out_bytes> <best_ms> <MB/s>" (MB = 1e6 bytes of output).
 */
#include <bzlib.h>
#include <lzma.h>
#include <zlib.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(n ? n : 1);
    if (n && fread(buf, 1, n, f) != (size_t)n) { perror("read"); exit(2); }
    fclose(f);
    *len = n;
    return buf;
}

/* Decodes `in` into `out` (capacity cap). Returns bytes produced, or (size_t)-1 on error or
 * if the output does not fit. */
static size_t decode(const char *codec, const unsigned char *in, size_t in_len, unsigned char *out, size_t cap) {
    if (!strcmp(codec, "xz") || !strcmp(codec, "xz-mt") || !strcmp(codec, "lzma")) {
        lzma_stream s = LZMA_STREAM_INIT;
        lzma_ret r;
        if (!strcmp(codec, "lzma")) {
            r = lzma_alone_decoder(&s, UINT64_MAX);
        } else if (!strcmp(codec, "xz-mt")) {
            lzma_mt mt;
            memset(&mt, 0, sizeof mt);
            mt.flags = LZMA_CONCATENATED;
            mt.threads = lzma_cputhreads();
            if (mt.threads == 0) mt.threads = 1;
            mt.memlimit_threading = UINT64_MAX;
            mt.memlimit_stop = UINT64_MAX;
            r = lzma_stream_decoder_mt(&s, &mt);
        } else {
            r = lzma_stream_decoder(&s, UINT64_MAX, LZMA_CONCATENATED);
        }
        if (r != LZMA_OK) return (size_t)-1;
        s.next_in = in;
        s.avail_in = in_len;
        s.next_out = out;
        s.avail_out = cap;
        r = lzma_code(&s, LZMA_FINISH);
        size_t n = cap - s.avail_out;
        lzma_end(&s);
        return r == LZMA_STREAM_END ? n : (size_t)-1;
    }
    if (!strcmp(codec, "gzip") || !strcmp(codec, "zlib") || !strcmp(codec, "deflate")) {
        int wbits = !strcmp(codec, "gzip") ? 31 : !strcmp(codec, "zlib") ? 15 : -15;
        z_stream z;
        memset(&z, 0, sizeof z);
        if (inflateInit2(&z, wbits) != Z_OK) return (size_t)-1;
        z.next_in = (unsigned char *)in;
        z.avail_in = in_len;
        z.next_out = out;
        z.avail_out = cap;
        int r;
        for (;;) {
            /* avail_in/avail_out are uInt: feed in chunks for > 4 GiB inputs (not needed here). */
            r = inflate(&z, Z_FINISH);
            if (r == Z_STREAM_END && wbits == 31 && z.avail_in > 0 && z.next_in[0] == 0x1f) {
                inflateReset(&z); /* next gzip member */
                continue;
            }
            break;
        }
        size_t n = cap - z.avail_out;
        inflateEnd(&z);
        return r == Z_STREAM_END ? n : (size_t)-1;
    }
    if (!strcmp(codec, "bz2")) {
        size_t produced = 0;
        size_t off = 0;
        while (off < in_len) {
            bz_stream b;
            memset(&b, 0, sizeof b);
            if (BZ2_bzDecompressInit(&b, 0, 0) != BZ_OK) return (size_t)-1;
            b.next_in = (char *)in + off;
            b.avail_in = in_len - off;
            b.next_out = (char *)out + produced;
            b.avail_out = cap - produced;
            int r = BZ2_bzDecompress(&b);
            size_t used = (in_len - off) - b.avail_in;
            produced = cap - b.avail_out;
            BZ2_bzDecompressEnd(&b);
            if (r != BZ_STREAM_END) return (size_t)-1;
            off += used; /* multi-stream: continue with the next "BZh" stream */
        }
        return produced;
    }
    fprintf(stderr, "unknown codec %s\n", codec);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s CODEC FILE RUNS [EXPECTED]\n", argv[0]);
        return 2;
    }
    const char *codec = argv[1];
    size_t in_len;
    unsigned char *in = read_file(argv[2], &in_len);
    int runs = atoi(argv[3]);

    /* Find the output size with a generous buffer. */
    size_t cap = in_len * 16 + (1 << 20);
    size_t n;
    for (;;) {
        unsigned char *probe = malloc(cap);
        n = decode(codec, in, in_len, probe, cap);
        if (n != (size_t)-1 && n < cap) {
            if (argc > 4) {
                size_t elen;
                unsigned char *exp = read_file(argv[4], &elen);
                if (elen != n || memcmp(exp, probe, n)) {
                    fprintf(stderr, "%s: output differs from %s\n", argv[2], argv[4]);
                    return 1;
                }
                free(exp);
            }
            free(probe);
            break;
        }
        free(probe);
        if (cap > ((size_t)1 << 36)) {
            fprintf(stderr, "%s: decode error\n", argv[2]);
            return 1;
        }
        cap *= 4;
    }

    double best = 1e30;
    unsigned sink = 0;
    for (int i = 0; i < runs; i++) {
        double t = now();
        unsigned char *out = malloc(n ? n : 1);
        size_t m = decode(codec, in, in_len, out, n);
        double dt = now() - t;
        if (m != n) { fprintf(stderr, "decode failed\n"); return 1; }
        sink += n ? out[n / 2] : 0;
        free(out);
        if (dt < best) best = dt;
    }
    printf("c %s %s %zu %.3f %.1f\n", codec, argv[2], n, best * 1e3, n / best / 1e6);
    return sink == 0xFFFFFFFF;
}
