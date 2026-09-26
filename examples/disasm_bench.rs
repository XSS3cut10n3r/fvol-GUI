//! Throughput benchmark of src/disasm/x86, the Rust side of bench/refbench/capstone_bench.c
//! (same corpus, methodology and output format; see that file for the workload definitions).
//!
//!   cargo build --release --example disasm_bench
//!   bench/scripts/limit.sh -m 4G target/release/examples/disasm_bench [DIR] [PASSES] [WORKLOADS]
//!
//! Workloads: text (decode + write_mnemonic + write_op_str into reused Strings), line (the
//! format_capstone renderer line into a reused buffer), detail (decode with structured operands),
//! cdetail (decode + capstone's detail view: `detail_operands` + `implicit_regs`, the work
//! capstone's CS_OPT_DETAIL does; its check equals capstone's detail check), len (length-only
//! `insn_len`). Each corpus section is swept linearly, skipping one byte after an
//! undecodable instruction. The `check` column must equal capstone's for text / line / len.

#[allow(dead_code)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use disasm::x86::{self, Insn, Mode};
use std::time::Instant;

struct Chunk {
    addr: u64,
    off: usize,
    len: usize,
}

fn load(dir: &str, bits: u32) -> Option<(Vec<u8>, Vec<Chunk>)> {
    let data = std::fs::read(format!("{dir}/real{bits}.bin")).ok()?;
    let idx = std::fs::read_to_string(format!("{dir}/real{bits}.idx")).ok()?;
    let mut chunks = Vec::new();
    let mut off = 0usize;
    for line in idx.lines() {
        let mut it = line.split_whitespace();
        let (Some(a), Some(l)) = (it.next(), it.next()) else { continue };
        let (Ok(addr), Ok(len)) = (u64::from_str_radix(a, 16), l.parse::<usize>()) else { continue };
        if off + len > data.len() {
            break;
        }
        chunks.push(Chunk { addr, off, len });
        off += len;
    }
    Some((data, chunks))
}

#[derive(Default, Clone, Copy)]
struct Res {
    insns: u64,
    bad: u64,
    bytes: u64,
    check: u64,
}

#[inline(never)]
fn run_text(data: &[u8], chunks: &[Chunk], mode: Mode) -> Res {
    let mut r = Res::default();
    let mut insn = Insn::default();
    let mut mn = String::with_capacity(64);
    let mut ops = String::with_capacity(256);
    for c in chunks {
        let buf = &data[c.off..c.off + c.len];
        r.bytes += c.len as u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            let addr = c.addr.wrapping_add(pos as u64);
            if x86::decode_into(&buf[pos..], addr, mode, &mut insn) {
                mn.clear();
                ops.clear();
                insn.write_mnemonic(&mut mn);
                insn.write_op_str(&mut ops);
                r.check += (mn.len() + ops.len()) as u64;
                r.insns += 1;
                pos += insn.size as usize;
            } else {
                r.bad += 1;
                pos += 1;
            }
        }
    }
    r
}

#[inline(never)]
fn run_line(data: &[u8], chunks: &[Chunk], mode: Mode) -> Res {
    const CAP: usize = 1 << 20;
    let mut r = Res::default();
    let mut insn = Insn::default();
    let mut out = String::with_capacity(CAP);
    for c in chunks {
        let buf = &data[c.off..c.off + c.len];
        r.bytes += c.len as u64;
        let mut pos = 0usize;
        out.clear();
        while pos < buf.len() {
            let addr = c.addr.wrapping_add(pos as u64);
            if x86::decode_into(&buf[pos..], addr, mode, &mut insn) {
                if out.len() + 512 > CAP {
                    r.check += out.len() as u64;
                    out.clear();
                }
                // the format_capstone line (same call as disasm::format_capstone_into)
                insn.write_line(&mut out);
                r.insns += 1;
                pos += insn.size as usize;
            } else {
                r.bad += 1;
                pos += 1;
            }
        }
        r.check += out.len() as u64;
    }
    r
}

#[inline(never)]
fn run_detail(data: &[u8], chunks: &[Chunk], mode: Mode) -> Res {
    let mut r = Res::default();
    let mut insn = Insn::default();
    for c in chunks {
        let buf = &data[c.off..c.off + c.len];
        r.bytes += c.len as u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            let addr = c.addr.wrapping_add(pos as u64);
            if x86::decode_into(&buf[pos..], addr, mode, &mut insn) {
                r.check += insn.op_count as u64 + insn.size as u64;
                r.insns += 1;
                pos += insn.size as usize;
            } else {
                r.bad += 1;
                pos += 1;
            }
        }
    }
    r
}

#[inline(never)]
fn run_cdetail(data: &[u8], chunks: &[Chunk], mode: Mode) -> Res {
    let mut r = Res::default();
    let mut insn = Insn::default();
    for c in chunks {
        let buf = &data[c.off..c.off + c.len];
        r.bytes += c.len as u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            let addr = c.addr.wrapping_add(pos as u64);
            if x86::decode_into(&buf[pos..], addr, mode, &mut insn) {
                let ops = insn.detail_operands();
                let (rd, wr) = insn.implicit_regs();
                r.check += (ops.len() + rd.len() + wr.len()) as u64;
                r.insns += 1;
                pos += insn.size as usize;
            } else {
                r.bad += 1;
                pos += 1;
            }
        }
    }
    r
}

#[inline(never)]
fn run_len(data: &[u8], chunks: &[Chunk], mode: Mode) -> Res {
    let mut r = Res::default();
    for c in chunks {
        let buf = &data[c.off..c.off + c.len];
        r.bytes += c.len as u64;
        let mut pos = 0usize;
        while pos < buf.len() {
            let n = x86::insn_len(&buf[pos..], mode);
            if n != 0 {
                r.check += n as u64;
                r.insns += 1;
                pos += n;
            } else {
                r.bad += 1;
                pos += 1;
            }
        }
    }
    r
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args.first().cloned().unwrap_or_else(|| "/home/user/rs-vol/testdata/scratch/disasm/ref/bin".into());
    let passes: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let only = args.get(2).cloned();
    // build the tables outside the timed region (capstone's are static data)
    let _ = x86::insn_len(&[0x90], Mode::X86_64);
    println!("# rsvol x86  passes={passes}  corpus={dir}");
    println!(
        "{:<6} {:<7} {:>10} {:>10} {:>10} {:>9} {:>12} {:>9} check",
        "side", "work", "mode", "insns", "bytes", "best_s", "insn/s", "MB/s"
    );
    let works: [(&str, fn(&[u8], &[Chunk], Mode) -> Res); 5] = [
        ("text", run_text),
        ("line", run_line),
        ("detail", run_detail),
        ("cdetail", run_cdetail),
        ("len", run_len),
    ];
    for bits in [32u32, 64] {
        let Some((data, chunks)) = load(&dir, bits) else {
            eprintln!("cannot read corpus real{bits} in {dir}");
            std::process::exit(1);
        };
        let mode = if bits == 64 { Mode::X86_64 } else { Mode::X86_32 };
        for (name, f) in works {
            if let Some(o) = &only {
                if !o.split(',').any(|x| x == name) {
                    continue;
                }
            }
            let mut best = f64::MAX;
            let mut r = Res::default();
            for _ in 0..passes {
                let t0 = Instant::now();
                r = std::hint::black_box(f(&data, &chunks, mode));
                best = best.min(t0.elapsed().as_secs_f64());
            }
            println!(
                "{:<6} {:<7} {:>10} {:>10} {:>10} {:>9.4} {:>12.0} {:>9.1} {}",
                "rust",
                name,
                if bits == 64 { "x86-64" } else { "x86-32" },
                r.insns,
                r.bytes,
                best,
                r.insns as f64 / best,
                r.bytes as f64 / best / 1e6,
                r.check
            );
            let _ = r.bad;
        }
    }
}
