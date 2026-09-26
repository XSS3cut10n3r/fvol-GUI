/* PCRE2-JIT reference harness for rsvol's regex engine (src/yara/regex).
 *
 * For every case of regex_cases.tsv: compile time (pcre2_compile + pcre2_jit_compile,
 * best of 20) and a python-`finditer`-equivalent loop of pcre2_jit_match over an mmapped
 * window of the memory image (best of REPS), counting non-overlapping matches:
 * after a match [s,e) the next search starts at e; after an empty match it retries at e
 * with PCRE2_NOTEMPTY_ATSTART|PCRE2_ANCHORED and otherwise advances one byte (pcre2demo /
 * python >= 3.7 semantics). 8-bit, non-UTF, non-UCP mode: \d \w \b and (?i) are ASCII,
 * like python bytes patterns.
 *
 * Output (one line per case):
 *   BENCH <TAB> pcre2-jit <TAB> case <TAB> compile_us <TAB> best_s <TAB> MB/s <TAB> matches <TAB> note
 *
 * Build: gcc -O3 -march=native -o regex_pcre2 regex_pcre2.c -lpcre2-8
 * Usage: regex_pcre2 IMG OFF LEN REPS CASES.tsv [case,case...]
 */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "benchutil.h"

static long scan(pcre2_code *re, pcre2_match_data *md, pcre2_match_context *mc, const unsigned char *hay, size_t len) {
    size_t pos = 0;
    uint32_t opts = 0;
    long n = 0;
    for (;;) {
        int rc = pcre2_jit_match(re, hay, len, pos, opts, md, mc);
        if (rc == PCRE2_ERROR_NOMATCH) {
            if (opts == 0) break;
            /* empty match at pos and no non-empty match anchored there: step one byte */
            opts = 0;
            if (++pos > len) break;
            continue;
        }
        if (rc < 0) {
            PCRE2_UCHAR msg[256];
            pcre2_get_error_message(rc, msg, sizeof msg);
            fprintf(stderr, "pcre2_jit_match error %d: %s at %zu\n", rc, (char *)msg, pos);
            return -1;
        }
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        n++;
        pos = ov[1];
        opts = ov[0] == ov[1] ? (PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED) : 0;
    }
    return n;
}

/* If the pattern is a plain literal (only \xHH and \<punct> escapes), decode it into out and
 * return its length, else -1. */
static long literal_of(const char *p, size_t n, unsigned char *out) {
    long k = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c == '\\') {
            if (i + 1 >= n) return -1;
            unsigned char e = (unsigned char)p[i + 1];
            if (e == 'x' && i + 3 < n) {
                char h[3] = {p[i + 2], p[i + 3], 0};
                out[k++] = (unsigned char)strtoul(h, NULL, 16);
                i += 3;
                continue;
            }
            if ((e >= '0' && e <= '9') || (e >= 'a' && e <= 'z') || (e >= 'A' && e <= 'Z')) return -1;
            out[k++] = e;
            i++;
            continue;
        }
        if (strchr(".^$*+?()[]{}|", c)) return -1;
        out[k++] = c;
    }
    return k;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s IMG OFF LEN REPS CASES.tsv [case,case...]\n", argv[0]);
        return 2;
    }
    size_t off = bu_size(argv[2]), len = bu_size(argv[3]);
    int reps = atoi(argv[4]);
    const unsigned char *hay = bu_map_window(argv[1], off, &len);
    bu_warm(hay, len);
    char *buf = bu_read_file(argv[5], NULL);
    char *names[BU_MAX_CASES], *pats[BU_MAX_CASES];
    size_t lens[BU_MAX_CASES];
    int nc = bu_parse_cases(buf, names, pats, lens);

    pcre2_match_context *mc = pcre2_match_context_create(NULL);
    pcre2_jit_stack *js = pcre2_jit_stack_create(32 * 1024, 4 * 1024 * 1024, NULL);
    pcre2_jit_stack_assign(mc, NULL, js);

    for (int c = 0; c < nc; c++) {
        if (!bu_selected(argc > 6 ? argv[6] : NULL, names[c])) continue;
        int err;
        PCRE2_SIZE erroff;
        double best_c = 1e9;
        pcre2_code *re = NULL;
        for (int i = 0; i < 20; i++) {
            if (re) pcre2_code_free(re);
            double t0 = bu_now();
            re = pcre2_compile((PCRE2_SPTR)pats[c], lens[c], 0, &err, &erroff, NULL);
            if (re && pcre2_jit_compile(re, PCRE2_JIT_COMPLETE) != 0) {
                fprintf(stderr, "%s: JIT compile failed\n", names[c]);
                pcre2_code_free(re);
                re = NULL;
            }
            double dt = bu_now() - t0;
            if (dt < best_c) best_c = dt;
            if (!re) break;
        }
        if (!re) {
            printf("BENCH\tpcre2-jit\t%s\t-\t-\t-\t-\tcompile error\n", names[c]);
            continue;
        }
        pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
        double best = 1e9;
        long count = -1;
        for (int r = 0; r < reps; r++) {
            double t0 = bu_now();
            long n = scan(re, md, mc, hay, len);
            double dt = bu_now() - t0;
            if (dt < best) best = dt;
            count = n;
        }
        printf("BENCH\tpcre2-jit\t%s\t%.1f\t%.4f\t%.1f\t%ld\twindow=%zuMiB\n", names[c], best_c * 1e6, best,
               (double)len / 1e6 / best, count, len >> 20);
        fflush(stdout);
        pcre2_match_data_free(md);
        pcre2_code_free(re);
        /* the substring-search floor: glibc memmem over the same window */
        unsigned char lit[512];
        long ll = lens[c] < sizeof lit ? literal_of(pats[c], lens[c], lit) : -1;
        if (ll > 1) {
            double bm = 1e9;
            long cnt = 0;
            for (int r = 0; r < reps; r++) {
                double t0 = bu_now();
                long k = 0;
                const unsigned char *p = hay, *end = hay + len;
                while ((p = memmem(p, (size_t)(end - p), lit, (size_t)ll)) != NULL) {
                    k++;
                    p++;
                }
                double dt = bu_now() - t0;
                if (dt < bm) bm = dt;
                cnt = k;
            }
            printf("PRIM\tglibc-memmem\t%s\t%.4f\t%.1f\t%ld\n", names[c], bm, (double)len / 1e6 / bm, cnt);
            fflush(stdout);
        }
    }
    return 0;
}
