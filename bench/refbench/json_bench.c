// Reference JSON parse speed (yyjson DOM, cJSON) for comparison with rsvol's util::json.
// Build: gcc -O3 -march=native -o json_bench json_bench.c -lyyjson -lcjson
// Run:   ./json_bench file.json
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <yyjson.h>
#include <cjson/cJSON.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(n + 1);
    if (fread(buf, 1, n, f) != (size_t)n) return 1;
    buf[n] = 0;
    fclose(f);
    double mb = n / 1e6, best = 1e9;
    for (int i = 0; i < 10; i++) {
        double t = now();
        yyjson_doc *d = yyjson_read(buf, n, 0);
        double e = now() - t;
        if (!d) return 2;
        yyjson_doc_free(d);
        if (e < best) best = e;
    }
    printf("yyjson DOM: %.2fms (%.0f MB/s)\n", best * 1e3, mb / best);
    best = 1e9;
    for (int i = 0; i < 5; i++) {
        double t = now();
        cJSON *j = cJSON_ParseWithLength(buf, n);
        double e = now() - t;
        if (!j) return 3;
        cJSON_Delete(j);
        if (e < best) best = e;
    }
    printf("cJSON DOM:  %.2fms (%.0f MB/s)\n", best * 1e3, mb / best);
    return 0;
}
