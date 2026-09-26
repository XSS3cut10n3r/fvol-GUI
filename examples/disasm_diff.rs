//! Differential tester / benchmark for src/disasm against capstone reference corpora
//! produced by bench/scripts/disasm_diff.py.
//!
//!   cargo run --profile fast --example disasm_diff -- cmp /tmp/rsvol-disasm [--only real64,rand32] [--show N]
//!   cargo run --release --example disasm_diff -- bench /tmp/rsvol-disasm/real64.bin ...
//!
//! `cmp` compares every reference line (count, mode, addr, window, size, mnemonic, op_str) with
//! our decoder and prints mismatch rates per corpus (unique lines and occurrence weighted);
//! all mismatches are written to DIR/NAME.mis.

#[allow(dead_code)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use disasm::x86::{self, Insn, Mode};
use std::io::{BufRead, BufWriter, Write};
use std::time::Instant;

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let v = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    };
    (0..b.len() / 2).map(|i| (v(b[2 * i]) << 4) | v(b[2 * i + 1])).collect()
}

fn cmp(dir: &str, only: Option<Vec<String>>, show: usize) {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".ref"))
        .map(|n| n.trim_end_matches(".ref").to_string())
        .collect();
    names.sort();
    let mut total_bad = 0u64;
    for name in names {
        if let Some(o) = &only {
            if !o.iter().any(|x| x == &name) {
                continue;
            }
        }
        let f = std::fs::File::open(format!("{dir}/{name}.ref")).expect("open ref");
        let mis = std::fs::File::create(format!("{dir}/{name}.mis")).expect("create mis");
        let mut mis = BufWriter::new(mis);
        let (mut uniq, mut ubad, mut wtot, mut wbad) = (0u64, 0u64, 0u64, 0u64);
        let mut shown = 0;
        let mut insn = Insn::default();
        let mut mn = String::new();
        let mut ops = String::new();
        let t0 = Instant::now();
        for line in std::io::BufReader::new(f).lines() {
            let line = line.unwrap();
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() < 7 {
                continue;
            }
            let count: u64 = p[0].parse().unwrap_or(1);
            let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
            let addr = u64::from_str_radix(p[2], 16).unwrap_or(0);
            let win = unhex(p[3]);
            let esize: u32 = p[4].parse().unwrap_or(0);
            let (emn, eop) = (p[5], p[6]);
            uniq += 1;
            wtot += count;
            let ok = x86::decode_into(&win, addr, mode, &mut insn);
            mn.clear();
            ops.clear();
            let gsize = if ok {
                insn.write_mnemonic(&mut mn);
                insn.write_op_str(&mut ops);
                insn.size as u32
            } else {
                0
            };
            let same = gsize == esize && (esize == 0 || (mn == emn && ops == eop));
            if !same {
                ubad += 1;
                wbad += count;
                writeln!(
                    mis,
                    "{count}\t{}\t{}\t{}\t{esize}\t{emn}\t{eop}\t{gsize}\t{mn}\t{ops}",
                    p[1], p[2], p[3]
                )
                .unwrap();
                if shown < show {
                    shown += 1;
                    println!("  {} {} exp {esize}:{emn} {eop} | got {gsize}:{mn} {ops}", p[1], p[3]);
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("cmp") => {
            let dir = args.get(1).cloned().unwrap_or_else(|| "/tmp/rsvol-disasm".into());
            let mut only = None;
            let mut show = 0;
            let mut i = 2;
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
            cmp(&dir, only, show);
        }
        Some("fmt") => {
            // fmt MODE HEX [ADDR]: print our decoding (for quick checks)
            let mode = if args.get(1).map(|s| s.as_str()) == Some("32") { Mode::X86_32 } else { Mode::X86_64 };
            for h in &args[2..] {
                let data = unhex(h);
                let arch = if mode == Mode::X86_64 { "intel64" } else { "intel" };
                println!("{h} => {:?}", disasm::format_capstone(&data, 0x1000, arch));
            }
        }
        _ => {
            eprintln!("usage: disasm_diff cmp DIR [--only a,b] [--show N] | fmt MODE HEX...");
            std::process::exit(2);
        }
    }
}
