//! Benchmark / differential drivers (ignored tests run by bench/scripts/*).
//! Owner: harness/benchmark owner.
//!
//! * `yara_regex_bench_driver` — regex throughput over an mmapped window of a memory image
//!   (bench/scripts/refbench.sh; same cases / window / output format as the reference
//!   harnesses in bench/refbench/ and bench/scripts/regex_bench.py).
//! * `yara_rules_bench_driver` — YARA compile + scan throughput (same rule files as
//!   bench/refbench/yara_bench.c).
//! * `yara_rules_difftest_driver` — YARA differential test vs yara-python
//!   (bench/scripts/yara_diff.py).
//!
//! Benchmark environment: `FASTVOL_BENCH_IMG` (image path), `FASTVOL_BENCH_OFF` / `FASTVOL_BENCH_LEN`
//! (window, default 1 GiB at 1 GiB; K/M/G suffixes ok), `FASTVOL_BENCH_REPS` (best of N,
//! default 5), `FASTVOL_BENCH_REGEX_CASES` (bench/refbench/regex_cases.tsv),
//! `FASTVOL_BENCH_YARA_CASES` (comma separated .yar files), `FASTVOL_BENCH_ONLY` (case name).
//! Output lines: `BENCH \t fastvol \t case \t compile_us \t best_s \t MB/s \t matches \t note`.

use super::regex::Regex;
use super::rules::{MetaValue, RuleMatch, Rules};
use std::collections::HashMap;
use std::fs::File;
use std::hint::black_box;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 1;
const MADV_WILLNEED: i32 = 3;

/// A read-only mapping of `[off, off+len)` of a file (never copied into memory).
struct Window {
    ptr: *mut u8,
    len: usize,
}

impl Window {
    fn map(path: &str, off: usize, len: usize) -> Window {
        let f = File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
        let size = f.metadata().expect("stat").len() as usize;
        assert!(off < size && off % 4096 == 0, "bad window offset {off:#x}");
        let len = len.min(size - off);
        let ptr = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_SHARED, f.as_raw_fd(), off as i64) };
        assert!(ptr as usize != usize::MAX, "mmap failed: {}", std::io::Error::last_os_error());
        unsafe {
            madvise(ptr, len, MADV_WILLNEED);
        }
        Window { ptr, len }
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Touch every page once (page cache + page tables), like `bu_warm` in benchutil.h.
    fn warm(&self) {
        let b = self.bytes();
        let mut acc = 0u32;
        let mut i = 0;
        while i < b.len() {
            acc = acc.wrapping_add(b[i] as u32);
            i += 4096;
        }
        black_box(acc);
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr, self.len);
        }
    }
}

fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    let (num, mul) = match s.as_bytes().last()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1usize << 10),
        b'm' | b'M' => (&s[..s.len() - 1], 1 << 20),
        b'g' | b'G' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    let v = match num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        Some(h) => usize::from_str_radix(h, 16).ok()?,
        None => num.parse().ok()?,
    };
    Some(v * mul)
}

fn env_size(name: &str, default: usize) -> usize {
    crate::util::env::var(name).ok().and_then(|v| parse_size(&v)).unwrap_or(default)
}

fn bench_window() -> Window {
    let img = crate::util::env::var("BENCH_IMG").unwrap_or_else(|_| "/home/user/cbc2/task2/memory-dirty.raw".into());
    let w = Window::map(&img, env_size("BENCH_OFF", 1 << 30), env_size("BENCH_LEN", 1 << 30));
    w.warm();
    w
}

fn secs_best<F: FnMut() -> T, T>(reps: usize, mut f: F) -> (f64, T) {
    let mut best = f64::MAX;
    let mut last = None;
    for _ in 0..reps.max(1) {
        let t = Instant::now();
        let r = black_box(f());
        best = best.min(t.elapsed().as_secs_f64());
        last = Some(r);
    }
    (best, last.unwrap())
}

/// The bytes a pattern matches if it is a plain literal (only `\xHH` / `\<punct>` escapes).
fn pattern_literal(p: &[u8]) -> Option<Vec<u8>> {
    let hexv = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        let c = p[i];
        if c == b'\\' {
            let n = *p.get(i + 1)?;
            if n == b'x' {
                out.push(hexv(*p.get(i + 2)?)? << 4 | hexv(*p.get(i + 3)?)?);
                i += 4;
                continue;
            }
            if n.is_ascii_alphanumeric() {
                return None;
            }
            out.push(n);
            i += 2;
            continue;
        }
        if b".^$*+?()[]{}|".contains(&c) {
            return None;
        }
        out.push(c);
        i += 1;
    }
    Some(out)
}

/// Regex throughput: `Regex::new(pattern, 0)` + `find_iter(window).count()`.
/// For plain-literal patterns also prints the substring primitive's own throughput
/// (`PRIM` line: `memchr::Memmem::find_iter`, the floor under the regex layer).
#[test]
#[ignore]
fn yara_regex_bench_driver() {
    let Ok(cases) = crate::util::env::var("BENCH_REGEX_CASES") else { return };
    let reps = env_size("BENCH_REPS", 5);
    let only = crate::util::env::var("BENCH_ONLY").unwrap_or_default();
    let data = std::fs::read(&cases).expect("read regex cases");
    let w = bench_window();
    let hay = w.bytes();
    for line in data.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(tab) = line.iter().position(|&b| b == b'\t') else { continue };
        let name = String::from_utf8_lossy(&line[..tab]).into_owned();
        let pat = &line[tab + 1..];
        if !only.is_empty() && !only.split(',').any(|o| o == name) {
            continue;
        }
        let (ctime, re) = secs_best(20, || Regex::new(pat, 0));
        let re = match re {
            Ok(r) => r,
            Err(e) => {
                println!("BENCH\tfastvol\t{name}\t-\t-\t-\t-\tcompile error: {e}");
                continue;
            }
        };
        let (best, n) = secs_best(reps, || re.find_iter(black_box(hay)).count());
        println!(
            "BENCH\tfastvol\t{name}\t{:.1}\t{best:.4}\t{:.1}\t{n}\twindow={}MiB engine={}",
            ctime * 1e6,
            hay.len() as f64 / 1e6 / best,
            hay.len() >> 20,
            re.engine_name()
        );
        if let Some(lit) = pattern_literal(pat).filter(|l| l.len() > 1) {
            let mm = super::memchr::Memmem::new(&lit);
            let (best, n) = secs_best(reps, || mm.find_iter(black_box(hay)).count());
            println!("PRIM\tfastvol-memmem\t{name}\t{best:.4}\t{:.1}\t{n}", hay.len() as f64 / 1e6 / best);
        }
    }
}

/// YARA throughput: `Rules::compile(src)` + `scan(window)` for every rule file.
#[test]
#[ignore]
fn yara_rules_bench_driver() {
    let Ok(files) = crate::util::env::var("BENCH_YARA_CASES") else { return };
    let reps = env_size("BENCH_REPS", 5);
    let only = crate::util::env::var("BENCH_ONLY").unwrap_or_default();
    let w = bench_window();
    let hay = w.bytes();
    for path in files.split(',').filter(|p| !p.is_empty()) {
        let name = std::path::Path::new(path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if !only.is_empty() && !only.split(',').any(|o| o == name) {
            continue;
        }
        let src = std::fs::read_to_string(path).expect("read rule file");
        let (ctime, rules) = secs_best(10, || Rules::compile(&src));
        let rules = match rules {
            Ok(r) => r,
            Err(e) => {
                println!("BENCH\tfastvol\t{name}\t-\t-\t-\t-\tpending ({e})");
                continue;
            }
        };
        let (best, (nr, ni)) = secs_best(reps, || {
            let m = rules.scan(black_box(hay));
            (m.len(), m.iter().flat_map(|r| r.strings.iter()).map(|s| s.instances.len()).sum::<usize>())
        });
        println!(
            "BENCH\tfastvol\t{name}\t{:.1}\t{best:.4}\t{:.1}\t{nr}/{ni}\twindow={}MiB",
            ctime * 1e6,
            hay.len() as f64 / 1e6 / best,
            hay.len() >> 20
        );
    }
}

/// Scan-API overheads and multi-thread scaling (developer probe, ignored test):
///   FASTVOL_BENCH_YARA_CASES=a.yar,b.yar [FASTVOL_BENCH_REGEX_CASES=cases.tsv] \
///   cargo test --profile release yara_scaling_probe -- --ignored --nocapture
/// * per-call cost of `Rules::scan` / `Regex::find_iter` on small buffers (vadyarascan
///   calls once per VAD): ns per call for 4 KiB and 64 KiB pieces of the window;
/// * throughput with T threads scanning disjoint 16 MiB chunks of the window (the
///   layer scanner's chunking), T = 1, 2, 4, 8, 16.
#[test]
#[ignore]
fn yara_scaling_probe() {
    let w = bench_window();
    let hay = w.bytes();
    type Job = Box<dyn Fn(&[u8]) -> usize + Sync>;
    let mut jobs: Vec<(String, Job)> = Vec::new();
    if let Ok(files) = crate::util::env::var("BENCH_YARA_CASES") {
        for path in files.split(',').filter(|p| !p.is_empty()) {
            let src = std::fs::read_to_string(path).expect("read rule file");
            let rules = Rules::compile(&src).expect("compile");
            let name = std::path::Path::new(path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            jobs.push((format!("yara {name}"), Box::new(move |d: &[u8]| rules.scan(d).len())));
        }
    }
    if let Ok(cases) = crate::util::env::var("BENCH_REGEX_CASES") {
        let data = std::fs::read(&cases).expect("read regex cases");
        for line in data.split(|&b| b == b'\n').filter(|l| !l.is_empty() && l[0] != b'#') {
            let Some(tab) = line.iter().position(|&b| b == b'\t') else { continue };
            let re = Regex::new(&line[tab + 1..], 0).expect("regex");
            jobs.push((format!("regex {}", String::from_utf8_lossy(&line[..tab])), Box::new(move |d: &[u8]| re.find_iter(d).count())));
        }
    }
    for (name, f) in &jobs {
        let mut per_call = Vec::new();
        for piece in [4096usize, 65536] {
            let n = (hay.len() / piece).min(16384);
            let (best, _) = secs_best(3, || (0..n).map(|i| f(&hay[i * piece..(i + 1) * piece])).sum::<usize>());
            per_call.push(format!("{}K: {:.0} ns/call ({:.0} MB/s)", piece >> 10, best * 1e9 / n as f64, (n * piece) as f64 / 1e6 / best));
        }
        let mut scaling = Vec::new();
        for threads in [1usize, 2, 4, 8, 16] {
            let chunk = 16 << 20;
            let nchunks = hay.len().div_ceil(chunk);
            let (best, _) = secs_best(3, || {
                let next = AtomicU64::new(0);
                std::thread::scope(|s| {
                    for _ in 0..threads {
                        s.spawn(|| {
                            let mut acc = 0usize;
                            loop {
                                let c = next.fetch_add(1, Ordering::Relaxed) as usize;
                                if c >= nchunks {
                                    break;
                                }
                                acc += f(&hay[c * chunk..((c + 1) * chunk).min(hay.len())]);
                            }
                            black_box(acc)
                        });
                    }
                });
            });
            scaling.push(format!("{threads}T {:.1}", hay.len() as f64 / 1e9 / best));
        }
        println!("{name:<16} {}  | GB/s {}", per_call.join("  "), scaling.join("  "));
    }
    // Shared-Regex contention: T threads calling `search` on 64-byte strings (scratch
    // space comes from the regex's pool on every call).
    if crate::util::env::var("BENCH_REGEX_CASES").is_ok() {
        let re = Regex::new(br"https?://[a-zA-Z0-9./?=_%:-]+", 0).expect("regex");
        let calls = 200_000usize;
        let mut row = Vec::new();
        for threads in [1usize, 2, 4, 8, 16] {
            let (best, _) = secs_best(3, || {
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let re = &re;
                        s.spawn(move || {
                            let mut acc = 0usize;
                            for i in 0..calls {
                                let off = ((i * 64 + t * 4096) % (hay.len() - 64)) & !63;
                                acc += re.search(&hay[off..off + 64], 0).is_some() as usize;
                            }
                            black_box(acc)
                        });
                    }
                });
            });
            row.push(format!("{threads}T {:.1}", (threads * calls) as f64 / 1e6 / best));
        }
        println!("regex search() on 64-byte strings, Mcalls/s: {}", row.join("  "));
    }
}

/// Where YARA scan time goes (developer probe, ignored test):
///   FASTVOL_BENCH_YARA_CASES=a.yar,... cargo test --profile release yara_verify_probe -- --ignored --nocapture
/// Per rule file: full scan, scan with hex/regex verification skipped, time inside
/// `ReString::verify`, and the candidate statistics of the matcher.
#[test]
#[ignore]
fn yara_verify_probe() {
    use super::scan::Matcher;
    use super::scan::matcher::{SKIP_VERIFY, TIME_VERIFY, VERIFY_CALLS, VERIFY_NS};
    let Ok(files) = crate::util::env::var("BENCH_YARA_CASES") else { return };
    let w = bench_window();
    let hay = w.bytes();
    for path in files.split(',').filter(|p| !p.is_empty()) {
        let src = std::fs::read_to_string(path).expect("read rule file");
        let rules = Rules::compile(&src).expect("compile");
        let m = Matcher::new(rules.string_defs()).expect("matcher");
        let mut out = Vec::new();
        let (full, _) = secs_best(3, || m.scan(hay, &mut out));
        let n: Vec<usize> = out.iter().map(|v| v.len()).collect();
        SKIP_VERIFY.store(true, Ordering::Relaxed);
        let (skip, _) = secs_best(3, || m.scan(hay, &mut out));
        SKIP_VERIFY.store(false, Ordering::Relaxed);
        TIME_VERIFY.store(true, Ordering::Relaxed);
        VERIFY_NS.store(0, Ordering::Relaxed);
        m.scan(hay, &mut out);
        let vns = VERIFY_NS.swap(0, Ordering::Relaxed);
        let calls = VERIFY_CALLS.swap(0, Ordering::Relaxed);
        TIME_VERIFY.store(false, Ordering::Relaxed);
        println!(
            "{path}: full {:.1} ms ({:.0} MB/s), verify skipped {:.1} ms, in verify {:.1} ms ({calls} calls); matches per string {n:?}",
            full * 1e3,
            hay.len() as f64 / 1e6 / full,
            skip * 1e3,
            vns as f64 * 1e-6
        );
        println!("{}", m.candidate_stats(hay));
    }
}

// ---------------------------------------------------------------------------------------
// YARA differential driver (bench/scripts/yara_diff.py)
// ---------------------------------------------------------------------------------------
//
// Input (`$FASTVOL_YARA_CASES`), tab separated, one record per line:
//   D  data_id  hex                        inline data buffer
//   F  data_id  path  offset  length       slice of a file (pread)
//   C  case_id  ns:srchex[,ns:srchex...]   data_id[,data_id...]
// case ids are 0..N in file order; `$FASTVOL_YARA_START` skips ids below it (resume after a
// crash), `$FASTVOL_YARA_TIMEOUT` (seconds, default 30) aborts the process with a TIMEOUT
// record when one case runs too long.
//
// Output (`$FASTVOL_YARA_OUT`, appended, flushed per case), tab separated:
//   id BEGIN
//   id COMPILE OK | id COMPILE ERR msg
//   id data M ns rule tags(space separated) meta(name=i:N | name=b:0/1 | name=s:hex, space separated)
//   id data S ns rule ident count md5(instances) first-instances(off:len:key:hexdata, space separated)
//   id DONE | id PANIC msg | id TIMEOUT
// md5 covers every instance line "off:len:key:hexdata\n" in reported order; at most
// `FIRST_INSTANCES` are listed explicitly.

const FIRST_INSTANCES: usize = 32;

fn unhex(s: &str) -> Vec<u8> {
    let v = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    };
    s.as_bytes().chunks(2).filter(|c| c.len() == 2).map(|c| v(c[0]) << 4 | v(c[1])).collect()
}

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn clean(s: &str) -> String {
    s.chars().map(|c| if c == '\t' || c == '\n' || c == '\r' { ' ' } else { c }).collect()
}

enum DataSpec {
    Inline(String),
    File(String, u64, usize),
}

fn load_data(spec: &DataSpec) -> Vec<u8> {
    match spec {
        DataSpec::Inline(h) => unhex(h),
        DataSpec::File(path, off, len) => {
            let f = File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
            let mut buf = vec![0u8; *len];
            let n = f.read_at(&mut buf, *off).unwrap_or(0);
            buf.truncate(n);
            buf
        }
    }
}

fn fmt_matches(id: usize, data_id: &str, ms: &[RuleMatch], out: &mut String) {
    use std::fmt::Write as _;
    for m in ms {
        let meta: Vec<String> = m
            .meta
            .iter()
            .map(|(k, v)| match v {
                MetaValue::Int(i) => format!("{k}=i:{i}"),
                MetaValue::Bool(b) => format!("{k}=b:{}", *b as u8),
                MetaValue::Str(s) => format!("{k}=s:{}", hex(s)),
            })
            .collect();
        let _ = writeln!(
            out,
            "{id}\t{data_id}\tM\t{}\t{}\t{}\t{}",
            clean(&m.namespace),
            clean(&m.rule),
            clean(&m.tags.join(" ")),
            meta.join(" ")
        );
        for s in &m.strings {
            let mut h = crate::crypto::md5::Md5::new();
            let mut first = Vec::new();
            for (k, i) in s.instances.iter().enumerate() {
                let line = format!("{}:{}:{}:{}", i.offset, i.matched_length, i.xor_key, hex(&i.matched_data));
                h.update(line.as_bytes());
                h.update(b"\n");
                if k < FIRST_INSTANCES {
                    first.push(line);
                }
            }
            let _ = writeln!(
                out,
                "{id}\t{data_id}\tS\t{}\t{}\t{}\t{}\t{}\t{}",
                clean(&m.namespace),
                clean(&m.rule),
                clean(&s.identifier),
                s.instances.len(),
                hex(&h.finalize()),
                first.join(" ")
            );
        }
    }
}

/// The record format must stay byte-identical to `py_case` in bench/scripts/yara_diff.py.
#[test]
fn difftest_record_format() {
    use super::rules::{Instance, StringMatch};
    let m = RuleMatch {
        rule: "r".into(),
        namespace: "default".into(),
        tags: vec!["t1".into(), "t2".into()],
        meta: vec![("a".into(), MetaValue::Int(-1)), ("b".into(), MetaValue::Bool(true)), ("c".into(), MetaValue::Str(b"x\xffy".to_vec()))],
        strings: vec![
            StringMatch {
                identifier: "$a".into(),
                instances: vec![
                    Instance { offset: 2, matched_data: b"abc".to_vec(), matched_length: 3, xor_key: 0 },
                    Instance { offset: 10, matched_data: b"`cb".to_vec(), matched_length: 3, xor_key: 1 },
                ],
            },
            StringMatch { identifier: "$p".into(), instances: vec![] },
        ],
    };
    let mut s = String::new();
    fmt_matches(7, "syn", &[m], &mut s);
    assert_eq!(
        s,
        "7\tsyn\tM\tdefault\tr\tt1 t2\ta=i:-1 b=b:1 c=s:78ff79\n\
         7\tsyn\tS\tdefault\tr\t$a\t2\t42077b9fefec23f40e003fdf6fe173fb\t2:3:0:616263 10:3:1:606362\n\
         7\tsyn\tS\tdefault\tr\t$p\t0\td41d8cd98f00b204e9800998ecf8427e\t\n"
    );
}

fn run_diff_case(id: usize, srcs: &[(String, String)], data_ids: &[String], data: &mut HashMap<String, Vec<u8>>, specs: &HashMap<String, DataSpec>) -> String {
    let refs: Vec<(&str, &str)> = srcs.iter().map(|(n, s)| (n.as_str(), s.as_str())).collect();
    let rules = match Rules::compile_namespaced(&refs) {
        Ok(r) => r,
        Err(e) => return format!("{id}\tCOMPILE\tERR\t{}\n", clean(&e.to_string())),
    };
    let mut out = format!("{id}\tCOMPILE\tOK\n");
    for d in data_ids {
        if !data.contains_key(d) {
            let Some(spec) = specs.get(d) else { continue };
            data.insert(d.clone(), load_data(spec));
        }
        let buf = &data[d];
        let ms = rules.scan(buf);
        fmt_matches(id, d, &ms, &mut out);
    }
    out
}

#[test]
#[ignore]
fn yara_rules_difftest_driver() {
    let Ok(inp) = crate::util::env::var("YARA_CASES") else { return };
    let outp = crate::util::env::var("YARA_OUT").unwrap_or_else(|_| format!("{inp}.out"));
    let start: usize = crate::util::env::var("YARA_START").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let timeout: f64 = crate::util::env::var("YARA_TIMEOUT").ok().and_then(|v| v.parse().ok()).unwrap_or(30.0);
    let text = std::fs::read_to_string(&inp).expect("read cases");
    let mut specs: HashMap<String, DataSpec> = HashMap::new();
    let mut cases: Vec<(usize, Vec<(String, String)>, Vec<String>)> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.first().copied() {
            Some("D") if f.len() >= 3 => {
                specs.insert(f[1].to_string(), DataSpec::Inline(f[2].to_string()));
            }
            Some("F") if f.len() >= 5 => {
                let off = f[3].parse().unwrap_or(0);
                let len = f[4].parse().unwrap_or(0);
                specs.insert(f[1].to_string(), DataSpec::File(f[2].to_string(), off, len));
            }
            Some("C") if f.len() >= 4 => {
                let Ok(id) = f[1].parse::<usize>() else { continue };
                let srcs = f[2]
                    .split(',')
                    .filter_map(|p| {
                        let (ns, h) = p.split_once(':')?;
                        Some((ns.to_string(), String::from_utf8_lossy(&unhex(h)).into_owned()))
                    })
                    .collect();
                let ds = f[3].split(',').filter(|s| !s.is_empty()).map(str::to_string).collect();
                cases.push((id, srcs, ds));
            }
            _ => {}
        }
    }
    let out = Arc::new(Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(&outp).expect("open out")));
    // Watchdog: a case running longer than `timeout` ends the process with a TIMEOUT record
    // (the harness resumes after it).
    const IDLE: u64 = u64::MAX;
    static CUR: AtomicU64 = AtomicU64::new(IDLE);
    static STARTED_MS: AtomicU64 = AtomicU64::new(0);
    let t0 = Instant::now();
    {
        let out = out.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(100));
                let cur = CUR.load(Ordering::SeqCst);
                if cur == IDLE {
                    continue;
                }
                let el = t0.elapsed().as_millis() as u64 - STARTED_MS.load(Ordering::SeqCst);
                if el as f64 > timeout * 1000.0 {
                    if let Ok(mut f) = out.lock() {
                        let _ = writeln!(f, "{cur}\tTIMEOUT");
                        let _ = f.flush();
                    }
                    std::process::exit(3);
                }
            }
        });
    }
    let mut data: HashMap<String, Vec<u8>> = HashMap::new();
    for (id, srcs, ds) in &cases {
        if *id < start {
            continue;
        }
        {
            let mut f = out.lock().unwrap();
            let _ = writeln!(f, "{id}\tBEGIN");
            let _ = f.flush();
        }
        STARTED_MS.store(t0.elapsed().as_millis() as u64, Ordering::SeqCst);
        CUR.store(*id as u64, Ordering::SeqCst);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_diff_case(*id, srcs, ds, &mut data, &specs)));
        CUR.store(IDLE, Ordering::SeqCst);
        let rec = match r {
            Ok(s) => format!("{s}{id}\tDONE\n"),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                format!("{id}\tPANIC\t{}\n", clean(&msg))
            }
        };
        let mut f = out.lock().unwrap();
        let _ = f.write_all(rec.as_bytes());
        let _ = f.flush();
    }
}
