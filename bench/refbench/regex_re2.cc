/* RE2 reference harness for fastvol's regex engine (src/yara/regex).
 *
 * For every case of regex_cases.tsv: compile time (RE2 constructor, best of 20) and a
 * find-all loop of RE2::Match(text, pos, len, UNANCHORED, &m, 1) over an mmapped window
 * of the memory image (best of REPS), counting non-overlapping matches (next search at the
 * end of the previous match). Options: Latin-1 encoding (patterns and text are bytes, like
 * python bytes patterns), max_mem 64 MiB (default 8 MiB can make the DFA bail out to the
 * NFA on large texts), leftmost-first (RE2's default, same priority rule as python / PCRE
 * for the patterns benchmarked; RE2 has no backrefs / lookaround, so only regular patterns
 * are comparable). Empty matches: RE2 cannot express "non-empty at this position", so after
 * an empty match the next search starts one byte later (differs from python only for
 * patterns that can match empty, none of the benchmark cases can).
 *
 * Output (one line per case):
 *   BENCH <TAB> re2 <TAB> case <TAB> compile_us <TAB> best_s <TAB> MB/s <TAB> matches <TAB> note
 *
 * Build: g++ -O3 -march=native -o regex_re2 regex_re2.cc $(pkg-config --cflags --libs re2)
 * Usage: regex_re2 IMG OFF LEN REPS CASES.tsv [case,case...]
 */
#include <re2/re2.h>

#include "benchutil.h"

static long scan(const RE2 &re, const unsigned char *hay, size_t len) {
    absl::string_view text(reinterpret_cast<const char *>(hay), len);
    absl::string_view m;
    size_t pos = 0;
    long n = 0;
    while (pos <= len && re.Match(text, pos, len, RE2::UNANCHORED, &m, 1)) {
        n++;
        size_t s = (size_t)(m.data() - text.data());
        size_t e = s + m.size();
        pos = e > s ? e : e + 1;
    }
    return n;
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

    RE2::Options opt;
    opt.set_encoding(RE2::Options::EncodingLatin1);
    opt.set_log_errors(false);
    opt.set_max_mem(64 << 20);

    for (int c = 0; c < nc; c++) {
        if (!bu_selected(argc > 6 ? argv[6] : NULL, names[c])) continue;
        absl::string_view pat(pats[c], lens[c]);
        double best_c = 1e9;
        bool ok = true;
        for (int i = 0; i < 20; i++) {
            double t0 = bu_now();
            RE2 *re = new RE2(pat, opt);
            ok = re->ok();
            double dt = bu_now() - t0;
            delete re;
            if (dt < best_c) best_c = dt;
            if (!ok) break;
        }
        if (!ok) {
            printf("BENCH\tre2\t%s\t-\t-\t-\t-\tcompile error\n", names[c]);
            continue;
        }
        RE2 re(pat, opt);
        double best = 1e9;
        long count = -1;
        for (int r = 0; r < reps; r++) {
            double t0 = bu_now();
            long n = scan(re, hay, len);
            double dt = bu_now() - t0;
            if (dt < best) best = dt;
            count = n;
        }
        printf("BENCH\tre2\t%s\t%.1f\t%.4f\t%.1f\t%ld\twindow=%zuMiB\n", names[c], best_c * 1e6, best,
               (double)len / 1e6 / best, count, len >> 20);
        fflush(stdout);
    }
    return 0;
}
