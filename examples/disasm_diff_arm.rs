//! Differential tester / benchmark for the ARM / AArch64 disassemblers (src/disasm/arm*)
//! against capstone, using the oracle tool bench/refbench/arm_oracle.c.
//!
//!   cargo run --profile fast --example disasm_diff_arm -- blocks arm64 0 100000000 20 [threads]
//!        same output as `arm_oracle blocks ...` (per-block FNV hashes) for exhaustive checks
//!   cargo run --profile fast --example disasm_diff_arm -- cmp arm64 REF.txt [--show N]
//!        compare against `arm_oracle dump/words/rand` output, print mismatches
//!   cargo run --release --example disasm_diff_arm -- bench arm64 N
//!        decode+format throughput on N pseudo-random words (same generator as arm_oracle rand)

#[allow(dead_code, unused_imports, unused_assignments)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use std::io::{BufRead, Write};
use std::time::Instant;

fn word_addr(w: u32) -> u64 {
    let mut z = (w as u64).wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    z & !3
}

fn render(arch: &str, w: u32, addr: u64, out: &mut String) -> bool {
    match arch {
        "arm64" => disasm::arm64::render_word(w, addr, out),
        "arm" => disasm::arm::render_word(w, addr, out),
        _ => false,
    }
}

const FNV_OFF: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv(mut h: u64, s: &[u8]) -> u64 {
    for &c in s {
        h ^= c as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h ^= b'\n' as u64;
    h.wrapping_mul(FNV_PRIME)
}

fn hash_cmd(args: &[String]) {
    let arch = args[0].clone();
    let start = u64::from_str_radix(&args[1], 16).unwrap();
    let end = u64::from_str_radix(&args[2], 16).unwrap();
    let bits: u32 = args[3].parse().unwrap();
    let nt: usize = args.get(4).and_then(|x| x.parse().ok()).unwrap_or(16);
    let nblocks = ((end - start + (1u64 << bits) - 1) >> bits) as usize;
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = std::sync::Mutex::new(vec![(0u64, 0u64); nblocks]);
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..nt {
            s.spawn(|| {
                let mut buf = String::with_capacity(256);
                loop {
                    let bi = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if bi >= nblocks {
                        break;
                    }
                    let s0 = start + ((bi as u64) << bits);
                    let e0 = (s0 + (1u64 << bits)).min(end);
                    let mut h = FNV_OFF;
                    let mut nv = 0u64;
                    for w in s0..e0 {
                        let w = w as u32;
                        buf.clear();
                        if render(&arch, w, word_addr(w), &mut buf) {
                            nv += 1;
                            h = fnv(h, buf.as_bytes());
                        } else {
                            h = fnv(h, b"!");
                        }
                    }
                    results.lock().unwrap()[bi] = (h, nv);
                }
            });
        }
    });
    eprintln!(
        "rust: {} words in {:.2}s",
        end - start,
        t0.elapsed().as_secs_f64()
    );
    let r = results.into_inner().unwrap();
    let stdout = std::io::stdout();
    let mut o = std::io::BufWriter::new(stdout.lock());
    for (i, (h, nv)) in r.iter().enumerate() {
        writeln!(o, "{} {:016x} {}", (start >> bits) + i as u64, h, nv).unwrap();
    }
}

fn cmp_cmd(args: &[String]) {
    let arch = args[0].clone();
    let f = std::fs::File::open(&args[1]).expect("open ref");
    let mut show = 20usize;
    if let Some(i) = args.iter().position(|a| a == "--show") {
        show = args[i + 1].parse().unwrap_or(20);
    }
    let (mut n, mut bad) = (0u64, 0u64);
    let mut buf = String::new();
    let mut kinds: std::collections::HashMap<String, (u64, String)> =
        std::collections::HashMap::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.unwrap();
        let mut it = line.splitn(3, '\t');
        let (Some(w), Some(a), Some(exp)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let w = u32::from_str_radix(w, 16).unwrap();
        let a = u64::from_str_radix(a, 16).unwrap();
        buf.clear();
        let ok = render(&arch, w, a, &mut buf);
        let got = if ok { buf.as_str() } else { "!" };
        n += 1;
        if got != exp {
            bad += 1;
            let key = format!(
                "{} / {}",
                exp.split('\t').next().unwrap_or(""),
                got.split('\t').next().unwrap_or("")
            );
            let e = kinds
                .entry(key)
                .or_insert((0, format!("{w:08x}  exp {exp:?}  got {got:?}")));
            e.0 += 1;
        }
    }
    let mut v: Vec<_> = kinds.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1.0));
    for (k, (c, ex)) in v.iter().take(show) {
        println!("{c:8} {k:30} {ex}");
    }
    println!(
        "{arch}: {n} words, {bad} mismatches ({:.5}%)",
        100.0 * bad as f64 / n.max(1) as f64
    );
    std::process::exit(if bad == 0 { 0 } else { 1 });
}

/// `mis ARCH FILE`: print "word\texpected\tgot" for every mismatch of an oracle dump.
fn mis_cmd(args: &[String]) {
    let arch = args[0].clone();
    let f = std::fs::File::open(&args[1]).expect("open ref");
    let mut buf = String::new();
    let stdout = std::io::stdout();
    let mut o = std::io::BufWriter::new(stdout.lock());
    for line in std::io::BufReader::new(f).lines() {
        let line = line.unwrap();
        let mut it = line.splitn(3, '\t');
        let (Some(w), Some(a), Some(exp)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let w = u32::from_str_radix(w, 16).unwrap();
        let a = u64::from_str_radix(a, 16).unwrap();
        buf.clear();
        let got = if render(&arch, w, a, &mut buf) {
            buf.as_str()
        } else {
            "!"
        };
        if got != exp {
            writeln!(
                o,
                "{w:08x}\t{}\t{}",
                exp.replace('\t', " "),
                got.replace('\t', " ")
            )
            .unwrap();
        }
    }
}

/// `corpora DIR [--only a,b] [--show N]`: compare the reference files written by
/// bench/scripts/disasm_diff_arm.py (count, mode, addr, word, size, mnemonic, op_str).
fn corpora_cmd(args: &[String]) {
    let dir = args[0].clone();
    let mut only: Option<Vec<String>> = None;
    let mut show = 0usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--only" => {
                only = Some(args[i + 1].split(',').map(|s| s.to_string()).collect());
                i += 1;
            }
            "--show" => {
                show = args[i + 1].parse().unwrap_or(0);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".ref"))
        .map(|n| n.trim_end_matches(".ref").to_string())
        .collect();
    names.sort();
    let mut total_bad = 0u64;
    for name in names {
        if let Some(o) = &only
            && !o.iter().any(|x| x == &name)
        {
            continue;
        }
        let f = std::fs::File::open(format!("{dir}/{name}.ref")).expect("open ref");
        let mis = std::fs::File::create(format!("{dir}/{name}.mis")).expect("create mis");
        let mut mis = std::io::BufWriter::new(mis);
        let (mut uniq, mut ubad, mut wtot, mut wbad) = (0u64, 0u64, 0u64, 0u64);
        let mut shown = 0;
        let mut buf = String::new();
        let t0 = Instant::now();
        for line in std::io::BufReader::new(f).lines() {
            let line = line.unwrap();
            let p: Vec<&str> = line.splitn(7, '\t').collect();
            if p.len() < 7 {
                continue;
            }
            let count: u64 = p[0].parse().unwrap_or(1);
            let arch = p[1];
            let addr = u64::from_str_radix(p[2], 16).unwrap_or(0);
            let b: Vec<u8> = (0..4)
                .map(|k| u8::from_str_radix(&p[3][2 * k..2 * k + 2], 16).unwrap_or(0))
                .collect();
            let w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let esize: u32 = p[4].parse().unwrap_or(0);
            uniq += 1;
            wtot += count;
            buf.clear();
            let ok = render(arch, w, addr, &mut buf);
            let exp = if esize == 0 {
                "!".to_string()
            } else {
                format!("{}\t{}", p[5], p[6])
            };
            let got = if ok { buf.as_str() } else { "!" };
            if got != exp {
                ubad += 1;
                wbad += count;
                writeln!(
                    mis,
                    "{count}\t{arch}\t{:x}\t{w:08x}\t{exp:?}\t{got:?}",
                    addr
                )
                .unwrap();
                if shown < show {
                    shown += 1;
                    println!("  {arch} {w:08x} exp {exp:?} | got {got:?}");
                }
            }
        }
        total_bad += ubad;
        println!(
            "{name:10} unique {uniq:9} mismatches {ubad:8} ({:.4}%)   weighted {wtot:10} mismatches {wbad:9} ({:.4}%)   [{:.1}s]",
            100.0 * ubad as f64 / uniq.max(1) as f64,
            100.0 * wbad as f64 / wtot.max(1) as f64,
            t0.elapsed().as_secs_f64()
        );
    }
    std::process::exit(if total_bad == 0 { 0 } else { 1 });
}

fn bench_cmd(args: &[String]) {
    let arch = args[0].clone();
    let n: usize = args
        .get(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(10_000_000);
    let mut words = Vec::with_capacity(n);
    if let Some(path) = args.get(2) {
        // real code: the file's words, repeated cyclically up to n words (like arm_bench.c)
        let data = std::fs::read(path).expect("read code file");
        let fw: Vec<u32> = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        for i in 0..n {
            words.push(fw[i % fw.len()]);
        }
    } else {
        let mut x: u64 = 1;
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            words.push((x >> 16) as u32);
        }
    }
    let t = Instant::now();
    let eng = if arch == "arm64" {
        disasm::arm64::engine_ref()
    } else {
        disasm::arm::engine_ref()
    };
    let (nc, no, nt, nl) = eng.sizes();
    println!(
        "spec compile {:.1} ms: {nc} classes, {no} ops, {nt} tree words, {nl} leaf entries",
        t.elapsed().as_secs_f64() * 1e3
    );
    let (mut sd, mut sl, mut sm) = (0u64, 0u64, 0u64);
    for &w in words.iter().take(1_000_000) {
        let (d, l, m) = eng.walk_stats(w);
        sd += d as u64;
        sl += l as u64;
        sm += m as u64;
    }
    let k = words.len().min(1_000_000) as f64;
    println!(
        "avg tree depth {:.2}, leaf size {:.2}, mask matches {:.2}",
        sd as f64 / k,
        sl as f64 / k,
        sm as f64 / k
    );
    let mut buf = String::with_capacity(256);
    {
        // split timing: valid-only vs invalid-only words
        let (mut vw, mut iw) = (Vec::new(), Vec::new());
        for &w in words.iter().take(2_000_000) {
            buf.clear();
            if render(&arch, w, 0x10000, &mut buf) {
                vw.push(w)
            } else {
                iw.push(w)
            }
        }
        for (name, set) in [("valid", &vw), ("invalid", &iw)] {
            let t = Instant::now();
            for &w in set.iter() {
                buf.clear();
                render(&arch, w, 0x10000, &mut buf);
            }
            let dt = t.elapsed().as_secs_f64();
            println!(
                "  {name}: {} words, {:.1} ns/word",
                set.len(),
                dt * 1e9 / set.len().max(1) as f64
            );
        }
    }
    for round in 0..3 {
        let t = Instant::now();
        let mut valid = 0u64;
        let mut bytes = 0u64;
        for &w in &words {
            buf.clear();
            if render(&arch, w, 0x10000, &mut buf) {
                valid += 1;
                bytes += buf.len() as u64;
            }
        }
        let dt = t.elapsed().as_secs_f64();
        println!(
            "round {round}: {n} words ({valid} valid) in {:.3}s = {:.2} M words/s, {:.2} M valid insn/s ({bytes} bytes)",
            dt,
            n as f64 / dt / 1e6,
            valid as f64 / dt / 1e6
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("blocks") => hash_cmd(&args[1..]),
        Some("cmp") => cmp_cmd(&args[1..]),
        Some("bench") => bench_cmd(&args[1..]),
        Some("mis") => mis_cmd(&args[1..]),
        Some("corpora") => corpora_cmd(&args[1..]),
        _ => eprintln!("usage: see source"),
    }
}
