// Reference JSON parsers on ISF files, for comparison with fastvol's ISF loader (src/symbols/isf.rs,
// src/util/json.rs). In-process, best of N, single thread:
//   * simdjson DOM (parser.parse: stage 1 + tape) and simdjson On-Demand walking every ISF field
//     fastvol extracts (types, fields, offsets, type descriptors, symbols, enums),
//   * yyjson DOM read (+ the same walk over the DOM).
// Build (simdjson is not packaged: fetch the single-header amalgamation, see isf_json_bench.sh):
//   g++ -O3 -march=native -std=c++17 -o isf_json_bench isf_json_bench.cc simdjson.cpp -lyyjson
// Run:   ./isf_json_bench file.json [N]
#include "simdjson.h"
#include <yyjson.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

using namespace simdjson;
static double now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

// ---- simdjson On-Demand ISF walk (the fields fastvol's builder reads) ----
static uint64_t od_desc(ondemand::object o);
static uint64_t od_desc_v(ondemand::value v) {
    ondemand::object o;
    if (v.get_object().get(o)) return 0;
    return od_desc(o);
}
static uint64_t od_desc(ondemand::object o) {
    uint64_t h = 0;
    for (auto f : o) {
        std::string_view k = f.unescaped_key().value();
        if (k == "kind" || k == "name") { std::string_view s; if (!f.value().get_string().get(s)) h += s.size(); }
        else if (k == "count" || k == "bit_position" || k == "bit_length") { int64_t x; if (!f.value().get_int64().get(x)) h += x; }
        else if (k == "subtype" || k == "type") h += od_desc_v(f.value());
    }
    return h;
}
static uint64_t od_walk(ondemand::parser &p, padded_string &json) {
    uint64_t h = 0;
    ondemand::document doc = p.iterate(json);
    for (auto sec : doc.get_object()) {
        std::string_view k = sec.unescaped_key().value();
        if (k == "user_types") {
            for (auto ut : sec.value().get_object()) {
                h += ut.unescaped_key().value().size();
                for (auto m : ut.value().get_object()) {
                    std::string_view mk = m.unescaped_key().value();
                    if (mk == "fields") {
                        for (auto fld : m.value().get_object()) {
                            h += fld.unescaped_key().value().size();
                            for (auto a : fld.value().get_object()) {
                                std::string_view ak = a.unescaped_key().value();
                                if (ak == "offset") { int64_t x; if (!a.value().get_int64().get(x)) h += x; }
                                else if (ak == "type") h += od_desc_v(a.value());
                                else if (ak == "anonymous") { bool b; if (!a.value().get_bool().get(b)) h += b; }
                            }
                        }
                    } else if (mk == "kind") { std::string_view s; if (!m.value().get_string().get(s)) h += s.size(); }
                    else if (mk == "size") { int64_t x; if (!m.value().get_int64().get(x)) h += x; }
                }
            }
        } else if (k == "symbols") {
            for (auto s : sec.value().get_object()) {
                h += s.unescaped_key().value().size();
                for (auto a : s.value().get_object()) {
                    std::string_view ak = a.unescaped_key().value();
                    if (ak == "address") { int64_t x; if (!a.value().get_int64().get(x)) h += x; }
                    else if (ak == "type") h += od_desc_v(a.value());
                    else if (ak == "constant_data") { std::string_view s2; if (!a.value().get_string().get(s2)) h += s2.size(); }
                }
            }
        } else if (k == "enums") {
            for (auto e : sec.value().get_object()) {
                h += e.unescaped_key().value().size();
                for (auto a : e.value().get_object()) {
                    std::string_view ak = a.unescaped_key().value();
                    if (ak == "base") { std::string_view s2; if (!a.value().get_string().get(s2)) h += s2.size(); }
                    else if (ak == "constants") {
                        for (auto c : a.value().get_object()) { int64_t x; h += c.unescaped_key().value().size(); if (!c.value().get_int64().get(x)) h += x; }
                    }
                }
            }
        } else if (k == "base_types") {
            for (auto b : sec.value().get_object()) {
                h += b.unescaped_key().value().size();
                for (auto a : b.value().get_object()) { h += a.unescaped_key().value().size(); }
            }
        } else if (k == "metadata") {
            (void)sec.value().raw_json();
        }
    }
    return h;
}

// ---- yyjson DOM walk ----
static uint64_t yy_desc(yyjson_val *o) {
    uint64_t h = 0;
    size_t idx, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(o, idx, max, k, v) {
        const char *ks = yyjson_get_str(k);
        if (!strcmp(ks, "kind") || !strcmp(ks, "name")) h += yyjson_get_len(v);
        else if (!strcmp(ks, "subtype") || !strcmp(ks, "type")) h += yy_desc(v);
        else if (yyjson_is_int(v)) h += yyjson_get_sint(v);
    }
    return h;
}
static uint64_t yy_walk(yyjson_doc *d) {
    uint64_t h = 0;
    yyjson_val *root = yyjson_doc_get_root(d);
    yyjson_val *uts = yyjson_obj_get(root, "user_types"), *syms = yyjson_obj_get(root, "symbols");
    size_t i1, m1, i2, m2, i3, m3;
    yyjson_val *k1, *v1, *k2, *v2, *k3, *v3;
    yyjson_obj_foreach(uts, i1, m1, k1, v1) {
        h += yyjson_get_len(k1);
        yyjson_val *fields = yyjson_obj_get(v1, "fields");
        h += yyjson_get_sint(yyjson_obj_get(v1, "size")) + yyjson_get_len(yyjson_obj_get(v1, "kind"));
        yyjson_obj_foreach(fields, i2, m2, k2, v2) {
            h += yyjson_get_len(k2);
            yyjson_obj_foreach(v2, i3, m3, k3, v3) {
                if (yyjson_is_obj(v3)) h += yy_desc(v3);
                else h += yyjson_get_sint(v3);
            }
        }
    }
    yyjson_obj_foreach(syms, i1, m1, k1, v1) {
        h += yyjson_get_len(k1);
        yyjson_obj_foreach(v1, i2, m2, k2, v2) {
            if (yyjson_is_obj(v2)) h += yy_desc(v2);
            else if (yyjson_is_int(v2)) h += yyjson_get_sint(v2);
            else h += yyjson_get_len(v2);
        }
    }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int reps = argc > 2 ? atoi(argv[2]) : 20;
    padded_string json = padded_string::load(argv[1]).value();
    double mb = json.size() / 1e6;
    auto best = [&](auto f) { double b = 1e9; for (int i = 0; i < reps; i++) { double t = now(); f(); b = std::min(b, now() - t); } return b; };
    printf("%s: %.1f MB, best of %d\n", argv[1], mb, reps);

    dom::parser dp;
    dom::element el;
    double t = best([&] { if (dp.parse(json).get(el)) exit(2); });
    printf("  simdjson %s DOM parse:        %7.2f ms  %6.0f MB/s\n", simdjson::get_active_implementation()->name().data(), t * 1e3, mb / t);
    {
        dom::parser fresh;  // includes the parser's first allocation, like a cold process
        double t0 = now();
        if (fresh.parse(json).get(el)) exit(2);
        printf("  simdjson DOM parse (fresh parser): %7.2f ms\n", (now() - t0) * 1e3);
    }
    ondemand::parser op;
    uint64_t h = 0;
    t = best([&] { h = od_walk(op, json); });
    printf("  simdjson On-Demand ISF walk:  %7.2f ms  %6.0f MB/s  (h=%llu)\n", t * 1e3, mb / t, (unsigned long long)h);

    t = best([&] { yyjson_doc *d = yyjson_read(json.data(), json.size(), 0); if (!d) exit(3); yyjson_doc_free(d); });
    printf("  yyjson DOM read:              %7.2f ms  %6.0f MB/s\n", t * 1e3, mb / t);
    t = best([&] { yyjson_doc *d = yyjson_read(json.data(), json.size(), 0); h = yy_walk(d); yyjson_doc_free(d); });
    printf("  yyjson DOM read + ISF walk:   %7.2f ms  %6.0f MB/s  (h=%llu)\n", t * 1e3, mb / t, (unsigned long long)h);
    return 0;
}
