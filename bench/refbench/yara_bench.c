/* libyara reference harness for fastvol's YARA engine (src/yara/rules + src/yara/scan).
 *
 * For every rule file given (bench/refbench/yara_cases/NAME.yar, the SAME text the rust
 * driver compiles): compile time (yr_compiler_create + add_string + get_rules, best of
 * 10) and yr_rules_scan_mem over an mmapped window of the memory image (best of REPS,
 * single thread, default flags + REPORT_RULES_MATCHING, i.e. what yara-python's
 * rules.match(data=...) does). Reports the number of matching (non-private) rules and the
 * number of match instances of non-private strings (what yara-python exposes as
 * StringMatch.instances; libyara keeps at most YR_MAX_STRING_MATCHES per string).
 *
 * Output (one line per rule file):
 *   BENCH <TAB> libyara <TAB> case <TAB> compile_us <TAB> best_s <TAB> MB/s <TAB> rules/instances <TAB> note
 *
 * Build: gcc -O3 -march=native -o yara_bench yara_bench.c -lyara
 * Usage: yara_bench IMG OFF LEN REPS file.yar [file.yar...]
 */
#include <yara.h>

#include "benchutil.h"

typedef struct {
    long rules;
    long instances;
    long too_many;
} Counts;

static int callback(YR_SCAN_CONTEXT *ctx, int message, void *message_data, void *user_data) {
    Counts *c = (Counts *)user_data;
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        if (RULE_IS_PRIVATE(rule)) return CALLBACK_CONTINUE;
        c->rules++;
        YR_STRING *s;
        yr_rule_strings_foreach(rule, s) {
            if (STRING_IS_PRIVATE(s)) continue;
            YR_MATCH *m;
            yr_string_matches_foreach(ctx, s, m) { c->instances++; }
        }
    } else if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {
        c->too_many++;
    }
    return CALLBACK_CONTINUE;
}

static void compiler_cb(int level, const char *file, int line, const YR_RULE *rule, const char *msg, void *ud) {
    (void)file; (void)rule; (void)ud;
    if (level == YARA_ERROR_LEVEL_ERROR) fprintf(stderr, "yara error line %d: %s\n", line, msg);
}

static YR_RULES *compile(const char *src) {
    YR_COMPILER *comp;
    if (yr_compiler_create(&comp) != ERROR_SUCCESS) return NULL;
    yr_compiler_set_callback(comp, compiler_cb, NULL);
    YR_RULES *rules = NULL;
    if (yr_compiler_add_string(comp, src, NULL) == 0) yr_compiler_get_rules(comp, &rules);
    yr_compiler_destroy(comp);
    return rules;
}

static const char *base(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s IMG OFF LEN REPS file.yar [file.yar...]\n", argv[0]);
        return 2;
    }
    size_t off = bu_size(argv[2]), len = bu_size(argv[3]);
    int reps = atoi(argv[4]);
    const unsigned char *hay = bu_map_window(argv[1], off, &len);
    bu_warm(hay, len);
    yr_initialize();
    for (int a = 5; a < argc; a++) {
        char name[256];
        snprintf(name, sizeof name, "%s", base(argv[a]));
        char *dot = strrchr(name, '.');
        if (dot) *dot = 0;
        char *src = bu_read_file(argv[a], NULL);
        double best_c = 1e9;
        YR_RULES *rules = NULL;
        for (int i = 0; i < 10; i++) {
            if (rules) yr_rules_destroy(rules);
            double t0 = bu_now();
            rules = compile(src);
            double dt = bu_now() - t0;
            if (dt < best_c) best_c = dt;
            if (!rules) break;
        }
        if (!rules) {
            printf("BENCH\tlibyara\t%s\t-\t-\t-\t-\tcompile error\n", name);
            continue;
        }
        double best = 1e9;
        Counts c = {0, 0, 0};
        for (int r = 0; r < reps; r++) {
            Counts cc = {0, 0, 0};
            double t0 = bu_now();
            int rc = yr_rules_scan_mem(rules, hay, len, SCAN_FLAGS_REPORT_RULES_MATCHING, callback, &cc, 0);
            double dt = bu_now() - t0;
            if (rc != ERROR_SUCCESS) fprintf(stderr, "%s: scan error %d\n", name, rc);
            if (dt < best) best = dt;
            c = cc;
        }
        printf("BENCH\tlibyara\t%s\t%.1f\t%.4f\t%.1f\t%ld/%ld\twindow=%zuMiB%s\n", name, best_c * 1e6, best,
               (double)len / 1e6 / best, c.rules, c.instances, len >> 20, c.too_many ? " too-many-matches" : "");
        fflush(stdout);
        yr_rules_destroy(rules);
        free(src);
    }
    yr_finalize();
    return 0;
}
