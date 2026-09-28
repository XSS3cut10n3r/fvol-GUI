//! Check `disasm::format_capstone` against the Disasm column of python volatility3 reference
//! outputs (bench/ref/py): windows.malware.malfind (bytes from its hexdump column) and
//! windows.mbrscan (boot code read from the raw memory image at the reported offsets).
//!
//!   cargo run --profile fast --example disasm_refcheck -- [REFDIR] [IMAGE]

#[allow(dead_code, unused_imports, unused_assignments)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use std::io::{Read, Seek, SeekFrom};

fn is_disasm_line(l: &str) -> bool {
    l.starts_with("0x") && l.contains(":\t") && !l.contains("\tN/A")
}

fn check_block(what: &str, got: &str, exp: &[&str], bad: &mut usize, total: &mut usize) {
    *total += 1;
    let g: Vec<&str> = got.split('\n').skip(1).collect();
    if g != exp {
        *bad += 1;
        if *bad <= 5 {
            eprintln!("MISMATCH {what}");
            for (i, (a, b)) in g.iter().zip(exp.iter()).enumerate() {
                if a != b {
                    eprintln!("  line {i}: got {a:?} exp {b:?}");
                    break;
                }
            }
            if g.len() != exp.len() {
                eprintln!("  len got {} exp {}", g.len(), exp.len());
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let refdir = args.get(1).cloned().unwrap_or_else(|| "/home/user/fvol/bench/ref/py".into());
    let image = args.get(2).cloned().unwrap_or_else(|| "/home/user/cbc2/task2/memory-dirty.raw".into());

    // ---------------------------------------------------------------- malfind
    let (mut bad, mut total) = (0usize, 0usize);
    if let Ok(txt) = std::fs::read_to_string(format!("{refdir}/windows.malware.malfind.Malfind.txt")) {
        let lines: Vec<&str> = txt.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let f: Vec<&str> = lines[i].split('\t').collect();
            if f.len() >= 10 && f[5].starts_with("PAGE_") {
                let start = u64::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
                let mut data = Vec::new();
                let mut j = i + 1;
                while j < lines.len() && data.len() < 64 {
                    for h in lines[j].split(' ').take(16) {
                        if let Ok(b) = u8::from_str_radix(h, 16) {
                            data.push(b);
                        }
                    }
                    j += 1;
                }
                let mut k = j;
                while k < lines.len() && is_disasm_line(lines[k]) {
                    k += 1;
                }
                let exp: Vec<&str> = lines[j..k].to_vec();
                let g64 = disasm::format_capstone(&data, start, "intel64");
                let g32 = disasm::format_capstone(&data, start, "intel");
                let g = if g64.split('\n').skip(1).collect::<Vec<_>>() == exp { g64 } else { g32 };
                check_block(&format!("malfind @{start:#x}"), &g, &exp, &mut bad, &mut total);
                i = k;
                continue;
            }
            i += 1;
        }
    }
    println!("malfind: {total} disassembly cells, {bad} mismatches");

    // ---------------------------------------------------------------- mbrscan
    let (mut bad, mut total) = (0usize, 0usize);
    if let (Ok(txt), Ok(mut img)) = (
        std::fs::read_to_string(format!("{refdir}/windows.mbrscan.MBRScan.txt")),
        std::fs::File::open(&image),
    ) {
        let lines: Vec<&str> = txt.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let f: Vec<&str> = lines[i].split('\t').collect();
            if f.len() >= 9 && f[0].starts_with("0x") && f[1].contains('-') {
                let off = u64::from_str_radix(f[0].trim_start_matches("0x"), 16).unwrap_or(0);
                let start = off.saturating_sub(0x1FE);
                let mut mbr = vec![0u8; 0x200];
                if img.seek(SeekFrom::Start(start)).is_ok() {
                    let mut got = 0;
                    while got < mbr.len() {
                        match img.read(&mut mbr[got..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got += n,
                        }
                    }
                }
                let boot = &mbr[..0x1B8];
                let mut k = i + 1;
                while k < lines.len() && is_disasm_line(lines[k]) {
                    k += 1;
                }
                let exp: Vec<&str> = lines[i + 1..k].to_vec();
                let g = disasm::format_capstone(boot, 0, "intel64");
                check_block(&format!("mbr @{off:#x}"), &g, &exp, &mut bad, &mut total);
                i = k;
                continue;
            }
            i += 1;
        }
    }
    println!("mbrscan: {total} disassembly cells, {bad} mismatches");
}
