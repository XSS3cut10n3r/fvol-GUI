/*
 * Reference codec throughput for rsvol's src/codecs (see run.sh).
 *
 *   refbench mkvec RAW_IMAGE OUTDIR NCHUNKS   write snappy.vec, xpress_huff.vec, xpress_lz77.vec
 *   refbench bench OUTDIR REPS                in-process decode throughput, best of REPS
 *
 * Vectors: 64 KiB chunks of real memory taken at evenly spaced offsets of the raw image
 * (all-zero chunks skipped), each stored as [u32 ulen][u32 clen][clen bytes].
 *   snappy.vec       libsnappy snappy_compress        -> reference: snappy_uncompress
 *   xpress_huff.vec  wimlib XPRESS (LZ77+Huffman)     -> reference: wimlib_decompress
 *   xpress_lz77.vec  samba lzxpress_compress (plain)  -> reference: lzxpress_decompress
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <snappy-c.h>
#include <wimlib.h>
#include "lzxpress.h"

#define CHUNK 65536

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void put(FILE *f, const void *c, uint32_t ulen, uint32_t clen) {
    fwrite(&ulen, 4, 1, f);
    fwrite(&clen, 4, 1, f);
    fwrite(c, 1, clen, f);
}

static int mkvec(const char *raw, const char *dir, long n) {
    int fd = open(raw, O_RDONLY);
    if (fd < 0) { perror(raw); return 1; }
    struct stat st;
    fstat(fd, &st);
    const uint8_t *m = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }
    char p[4096];
    snprintf(p, sizeof p, "%s/snappy.vec", dir);
    FILE *fs = fopen(p, "wb");
    snprintf(p, sizeof p, "%s/xpress_huff.vec", dir);
    FILE *fh = fopen(p, "wb");
    snprintf(p, sizeof p, "%s/xpress_lz77.vec", dir);
    FILE *fl = fopen(p, "wb");
    if (!fs || !fh || !fl) { perror("fopen"); return 1; }
    struct wimlib_compressor *wc;
    if (wimlib_create_compressor(WIMLIB_COMPRESSION_TYPE_XPRESS, CHUNK, 0, &wc)) { fprintf(stderr, "wimlib compressor\n"); return 1; }
    static uint8_t out[CHUNK * 2];
    long stride = (st.st_size / CHUNK) / n;
    if (stride < 1) stride = 1;
    long written = 0;
    for (long i = 0; written < n && (i * stride + 1) * CHUNK <= st.st_size; i++) {
        const uint8_t *in = m + i * stride * CHUNK;
        int zero = 1;
        for (int k = 0; k < CHUNK; k++) if (in[k]) { zero = 0; break; }
        if (zero) continue;
        size_t sl = sizeof out;
        snappy_compress((const char *)in, CHUNK, (char *)out, &sl);
        size_t hl = wimlib_compress(in, CHUNK, out + CHUNK, CHUNK - 1, wc);
        ssize_t ll = lzxpress_compress(in, CHUNK, out + 0, sizeof out);
        if (hl == 0 || ll <= 0) continue; /* incompressible for one of the formats */
        /* recompute snappy into its own buffer (lzxpress reused `out`) */
        static uint8_t sb[CHUNK * 2];
        sl = sizeof sb;
        snappy_compress((const char *)in, CHUNK, (char *)sb, &sl);
        static uint8_t hb[CHUNK];
        hl = wimlib_compress(in, CHUNK, hb, CHUNK - 1, wc);
        put(fs, sb, CHUNK, sl);
        put(fh, hb, CHUNK, hl);
        put(fl, out, CHUNK, ll);
        written++;
    }
    fclose(fs); fclose(fh); fclose(fl);
    printf("wrote %ld chunks of %d bytes\n", written, CHUNK);
    return 0;
}

struct vec { uint8_t *data; size_t len; };

static struct vec load(const char *dir, const char *name) {
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    FILE *f = fopen(p, "rb");
    struct vec v = {0};
    if (!f) { perror(p); exit(1); }
    fseek(f, 0, SEEK_END);
    v.len = ftell(f);
    fseek(f, 0, SEEK_SET);
    v.data = malloc(v.len);
    if (fread(v.data, 1, v.len, f) != v.len) { perror("read"); exit(1); }
    fclose(f);
    return v;
}

typedef int (*decode_fn)(const uint8_t *c, uint32_t clen, uint8_t *out, uint32_t ulen, void *ctx);

static int d_snappy(const uint8_t *c, uint32_t clen, uint8_t *out, uint32_t ulen, void *ctx) {
    (void)ctx;
    size_t l = ulen;
    return snappy_uncompress((const char *)c, clen, (char *)out, &l) != SNAPPY_OK || l != ulen;
}
static int d_huff(const uint8_t *c, uint32_t clen, uint8_t *out, uint32_t ulen, void *ctx) {
    return wimlib_decompress(c, clen, out, ulen, ctx);
}
static int d_lz77(const uint8_t *c, uint32_t clen, uint8_t *out, uint32_t ulen, void *ctx) {
    (void)ctx;
    return lzxpress_decompress(c, clen, out, ulen) != (ssize_t)ulen;
}

static void bench(const char *label, struct vec v, decode_fn fn, void *ctx, int reps) {
    static uint8_t out[CHUNK];
    double best = 1e30;
    size_t total = 0, chunks = 0, ctotal = 0;
    for (int r = 0; r < reps; r++) {
        double t = now();
        size_t off = 0;
        total = chunks = ctotal = 0;
        while (off + 8 <= v.len) {
            uint32_t ul, cl;
            memcpy(&ul, v.data + off, 4);
            memcpy(&cl, v.data + off + 4, 4);
            if (fn(v.data + off + 8, cl, out, ul, ctx)) { fprintf(stderr, "%s: decode error\n", label); exit(1); }
            total += ul;
            ctotal += cl;
            chunks++;
            off += 8 + cl;
        }
        t = now() - t;
        if (t < best) best = t;
    }
    printf("%-12s ref  %8.1f MB/s  (%zu chunks, ratio %.2f, best of %d)\n", label, total / best / 1e6, chunks,
           (double)total / ctotal, reps);
}

int main(int argc, char **argv) {
    if (argc >= 5 && !strcmp(argv[1], "mkvec")) return mkvec(argv[2], argv[3], atol(argv[4]));
    if (argc >= 4 && !strcmp(argv[1], "bench")) {
        int reps = atoi(argv[3]);
        struct wimlib_decompressor *wd;
        if (wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_XPRESS, CHUNK, &wd)) return 1;
        bench("snappy", load(argv[2], "snappy.vec"), d_snappy, NULL, reps);
        bench("xpress_huff", load(argv[2], "xpress_huff.vec"), d_huff, wd, reps);
        bench("xpress_lz77", load(argv[2], "xpress_lz77.vec"), d_lz77, NULL, reps);
        return 0;
    }
    fprintf(stderr, "usage: %s mkvec RAW OUTDIR N | bench OUTDIR REPS\n", argv[0]);
    return 2;
}
