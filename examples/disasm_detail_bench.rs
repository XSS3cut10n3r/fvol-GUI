//! Micro-benchmark of the capstone detail view (decode + detail operands + implicit regs +
//! regs_access) over the unique real-code windows of a reference corpus.
//!
//!   cargo run --release --example disasm_detail_bench -- [testdata/scratch/disasm/ref/real64.ref]

#[allow(dead_code)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use disasm::x86::{self, Insn, Mode};
use std::io::BufRead;
use std::time::Instant;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

fn best<F: FnMut() -> u64>(n: usize, mut f: F) -> (f64, u64) {
    let mut b = f64::MAX;
    let mut chk = 0;
    for _ in 0..n {
        let t = Instant::now();
        chk = f();
        b = b.min(t.elapsed().as_secs_f64());
    }
    (b, chk)
}

/// Streaming benchmark over a flat code corpus (`BIN` + `IDX` of "addr_hex\tlen" chunks): linear
/// sweep, skip one byte on invalid; decode only vs decode + detail_into.
fn stream(bin: &str, idx: &str, mode: Mode) {
    let data = std::fs::read(bin).expect("bin");
    let mut chunks = Vec::new();
    let mut off = 0usize;
    for l in std::fs::read_to_string(idx).expect("idx").lines() {
        let Some((a, n)) = l.split_once('\t') else { continue };
        let a = u64::from_str_radix(a, 16).unwrap_or(0);
        let n: usize = n.parse().unwrap_or(0);
        chunks.push((a, off, n.min(data.len().saturating_sub(off))));
        off += n;
    }
    let mut insn = Insn::default();
    let mut d = x86::Detail::new();
    for with_detail in [false, true] {
        let (t, c) = best(3, || {
            let mut cnt = 0u64;
            for &(a, o, n) in &chunks {
                let buf = &data[o..o + n];
                let mut p = 0usize;
                while p < buf.len() {
                    if x86::decode_into(&buf[p..], a + p as u64, mode, &mut insn) {
                        if with_detail {
                            insn.detail_into(&mut d);
                            cnt += d.regs_write.len() as u64;
                        }
                        p += insn.size as usize;
                        cnt += 1;
                    } else {
                        p += 1;
                    }
                }
            }
            cnt
        });
        let mut ninsn = 0u64;
        for &(a, o, n) in &chunks {
            let buf = &data[o..o + n];
            let mut p = 0usize;
            while p < buf.len() {
                if x86::decode_into(&buf[p..], a + p as u64, mode, &mut insn) {
                    p += insn.size as usize;
                    ninsn += 1;
                } else {
                    p += 1;
                }
            }
        }
        println!(
            "{} {:?}: {:.1} M insn/s ({:.1} ns/insn) chk {c}",
            if with_detail { "decode+detail_into" } else { "decode            " },
            mode,
            ninsn as f64 / t / 1e6,
            t / ninsn as f64 * 1e9
        );
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("stream") {
        let a: Vec<String> = std::env::args().collect();
        let mode = if a.get(4).map(|s| s.as_str()) == Some("32") { Mode::X86_32 } else { Mode::X86_64 };
        stream(&a[2], &a[3], mode);
        return;
    }
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/home/user/rs-vol/testdata/scratch/disasm/ref/real64.ref".into());
    let f = std::fs::File::open(&path).expect("open corpus");
    let mut wins: Vec<([u8; 15], u8, Mode, u64)> = Vec::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.unwrap();
        let p: Vec<&str> = line.split('\t').collect();
        if p.len() < 7 || p[4] == "0" {
            continue;
        }
        let mut w = [0u8; 15];
        let b = unhex(p[3]);
        w[..b.len()].copy_from_slice(&b);
        let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
        wins.push((w, b.len() as u8, mode, u64::from_str_radix(p[2], 16).unwrap_or(0)));
    }
    let mut insn = Insn::default();
    if std::env::args().nth(2).as_deref() == Some("profile") {
        // one pass of decode + detail() (for callgrind)
        wins.truncate(300_000);
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                let d = insn.detail();
                s += (d.ops.len() + d.regs_read.len() + d.regs_write.len()) as u64;
            }
        }
        println!("{s}");
        return;
    }
    let n = wins.len() as f64;
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                s += insn.size as u64;
            }
        }
        s
    });
    println!("decode            {:7.1} ns/insn  ({c})", t / n * 1e9);
    for (which, name) in [(0u8, "+prefixes"), (1, "+cs_operands"), (2, "+info")] {
        let (t, c) = best(5, || {
            let mut s = 0u64;
            for (w, l, m, a) in &wins {
                if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                    s += x86::_bench_part(&insn, which);
                }
            }
            s
        });
        println!("{name:17} {:7.1} ns/insn  ({c})", t / n * 1e9);
    }
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                s += insn.detail_operands().len() as u64;
            }
        }
        s
    });
    println!("+detail_operands  {:7.1} ns/insn  ({c})", t / n * 1e9);
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                let (r, w) = insn.regs_access();
                s += (r.len() + w.len()) as u64;
            }
        }
        s
    });
    println!("+regs_access      {:7.1} ns/insn  ({c})", t / n * 1e9);
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                let d = insn.detail();
                s += (d.ops.len() + d.regs_read.len() + d.regs_write.len() + d.implicit_read.len()
                    + d.implicit_write.len()) as u64;
            }
        }
        s
    });
    println!("+detail() (all)   {:7.1} ns/insn  ({c})", t / n * 1e9);
    let mut d = x86::Detail::new();
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                insn.detail_into(&mut d);
                s += (d.ops.len() + d.regs_read.len() + d.regs_write.len() + d.implicit_read.len()
                    + d.implicit_write.len()) as u64;
            }
        }
        s
    });
    println!("+detail_into      {:7.1} ns/insn  ({c})", t / n * 1e9);
    let (t, c) = best(5, || {
        let mut s = 0u64;
        for (w, l, m, a) in &wins {
            if x86::decode_into(&w[..*l as usize], *a, *m, &mut insn) {
                s += insn.detail_operands().len() as u64;
                let (r, w) = insn.implicit_regs();
                s += (r.len() + w.len()) as u64;
                let (r, w) = insn.regs_access();
                s += (r.len() + w.len()) as u64;
            }
        }
        s
    });
    println!("+3 accessors      {:7.1} ns/insn  ({c})", t / n * 1e9);
}
