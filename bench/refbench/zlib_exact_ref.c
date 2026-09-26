/*
 * Reference side for src/codecs/zlib_exact.rs (bit-exact port of zlib 1.3.2 deflate) and
 * src/codecs/png.rs (Pillow PNG writer): a differential oracle and a throughput harness,
 * both linked against the system zlib (the same libz.so.1 python's zlib module and Pillow use).
 *
 *   gcc -O3 -march=native -o zlib_exact_ref zlib_exact_ref.c -lz
 *
 * ORACLE (driven by the ignored test `zlib_exact_oracle` in zlib_exact.rs):
 *   zlib_exact_ref oracle LEVEL WBITS MEMLEVEL STRATEGY OUTCHUNK SCRIPT INFILE OUTFILE
 *     SCRIPT = "LEN:FLUSH,LEN:FLUSH,..." (LEN = input bytes for that step, '*' = the rest),
 *     or "Nr" = the input in N-byte Z_NO_FLUSH steps followed by "0:4".
 *     Each step: next_in = the next LEN input bytes; then
 *         do { avail_out = OUTCHUNK; ret = deflate(flush); trace; write } while (more)
 *     where more = avail_out == 0 || (flush == Z_FINISH && ret == Z_OK) (python's loop, plus
 *     finishing the stream), bounded to 1e6 calls in total (small OUTCHUNKs with Z_SYNC_FLUSH/Z_FULL_FLUSH loop forever: every call emits another empty stored block). OUTFILE receives the compressed bytes;
 *     stdout one "ret consumed produced" line per deflate() call (the Rust side replays the
 *     exact same call sequence and compares both).
 *
 * BENCH:
 *   zlib_exact_ref bench LEVEL WBITS MEMLEVEL STRATEGY FILE RUNS [ROWLEN]
 *     deflateInit2 + deflate of the whole file into a preallocated buffer, best of RUNS.
 *     With ROWLEN, the input is fed ROWLEN bytes per deflate(Z_NO_FLUSH) call and finished
 *     with Z_FINISH (Pillow's PNG encoder feeds one filtered scanline per call).
 *     Prints "c zlib LEVEL FILE IN_BYTES OUT_BYTES BEST_MS MB/s" (MB/s of input).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

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

static int oracle(int argc, char **argv) {
    if (argc != 10) { fprintf(stderr, "bad oracle args\n"); return 2; }
    int level = atoi(argv[2]), wbits = atoi(argv[3]), memlevel = atoi(argv[4]), strategy = atoi(argv[5]);
    size_t outchunk = strtoull(argv[6], NULL, 0);
    const char *script = argv[7];
    size_t inlen;
    unsigned char *in = read_file(argv[8], &inlen);
    FILE *out = fopen(argv[9], "wb");
    if (!out) { perror(argv[9]); return 2; }
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    int ret = deflateInit2(&zs, level, Z_DEFLATED, wbits, memlevel, strategy);
    if (ret != Z_OK) { printf("init %d\n", ret); fclose(out); return 0; }
    unsigned char *obuf = malloc(outchunk ? outchunk : 1);
    size_t pos = 0;
    long calls = 0;
    const char *p = script;
    /* "Nr": the whole input in N-byte Z_NO_FLUSH steps, then "0:4" */
    size_t slen = strlen(script);
    char *expanded = NULL;
    if (slen > 1 && script[slen - 1] == 'r') {
        size_t k = strtoull(script, NULL, 10);
        if (!k) k = 1;
        size_t steps = (inlen + k - 1) / k;
        expanded = malloc(steps * 24 + 8);
        char *w = expanded;
        for (size_t i = 0; i < steps; i++) w += sprintf(w, "%zu:0,", k);
        strcpy(w, "0:4");
        p = expanded;
    }
    while (*p) {
        size_t len;
        if (*p == '*') { len = inlen - pos; p++; }
        else { char *e; len = strtoull(p, &e, 10); p = e; }
        if (*p != ':') { fprintf(stderr, "bad script\n"); return 2; }
        p++;
        char *e;
        int flush = (int)strtol(p, &e, 10);
        p = e;
        if (*p == ',') p++;
        if (len > inlen - pos) len = inlen - pos;
        zs.next_in = in + pos;
        zs.avail_in = (uInt)len;
        int more;
        do {
            zs.next_out = obuf;
            zs.avail_out = (uInt)outchunk;
            uInt ai = zs.avail_in;
            ret = deflate(&zs, flush);
            size_t produced = outchunk - zs.avail_out;
            printf("%d %u %zu\n", ret, ai - zs.avail_in, produced);
            fwrite(obuf, 1, produced, out);
            more = zs.avail_out == 0 || (flush == Z_FINISH && ret == Z_OK);
            if (ret == Z_STREAM_ERROR) more = 0;
            calls++;
        } while (more && calls < 1000000);
        pos += len - zs.avail_in;
    }
    deflateEnd(&zs);
    fclose(out);
    free(expanded);
    return 0;
}

static int bench(int argc, char **argv) {
    if (argc < 8) { fprintf(stderr, "bad bench args\n"); return 2; }
    int level = atoi(argv[2]), wbits = atoi(argv[3]), memlevel = atoi(argv[4]), strategy = atoi(argv[5]);
    const char *path = argv[6];
    int runs = atoi(argv[7]);
    size_t rowlen = argc > 8 ? strtoull(argv[8], NULL, 0) : 0;
    size_t inlen;
    unsigned char *in = read_file(path, &inlen);
    size_t cap = inlen + inlen / 8 + 4096;
    unsigned char *obuf = malloc(cap);
    double best = 1e30;
    size_t outlen = 0;
    for (int r = 0; r < runs; r++) {
        z_stream zs;
        memset(&zs, 0, sizeof zs);
        double t0 = now();
        if (deflateInit2(&zs, level, Z_DEFLATED, wbits, memlevel, strategy) != Z_OK) return 2;
        zs.next_out = obuf;
        zs.avail_out = (uInt)cap;
        if (rowlen) {
            for (size_t pos = 0; pos < inlen; pos += rowlen) {
                size_t n = inlen - pos < rowlen ? inlen - pos : rowlen;
                zs.next_in = in + pos;
                zs.avail_in = (uInt)n;
                if (deflate(&zs, Z_NO_FLUSH) != Z_OK) return 3;
            }
        } else {
            zs.next_in = in;
            zs.avail_in = (uInt)inlen;
        }
        if (deflate(&zs, Z_FINISH) != Z_STREAM_END) return 4;
        outlen = zs.total_out;
        deflateEnd(&zs);
        double dt = now() - t0;
        if (dt < best) best = dt;
    }
    printf("c zlib %d %s %zu %zu %.3f %.1f\n", level, path, inlen, outlen, best * 1e3, inlen / best / 1e6);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "oracle")) return oracle(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "bench")) return bench(argc, argv);
    fprintf(stderr, "usage: zlib_exact_ref oracle|bench ...\n");
    return 2;
}
