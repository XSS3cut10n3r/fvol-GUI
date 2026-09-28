//! Disassembler tests: golden capstone outputs + (optional) large differential corpora.

use super::*;

fn fmt1(hex: &str, mode: Mode) -> String {
    let data: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    match decode(&data, 0x1000, mode) {
        Some(i) => format!("{}:{}\t{}", i.size, i.mnemonic(), i.op_str()),
        None => "INVALID".into(),
    }
}

#[test]
fn disasm_basic_x64() {
    let m = Mode::X86_64;
    assert_eq!(fmt1("4883c0ff", m), "4:add\trax, -1");
    assert_eq!(fmt1("48c7c0ffffffff", m), "7:mov\trax, 0xffffffffffffffff");
    assert_eq!(fmt1("8b05f0ffffff", m), "6:mov\teax, dword ptr [rip - 0x10]");
    assert_eq!(fmt1("65488b042560000000", m), "9:mov\trax, qword ptr gs:[0x60]");
    assert_eq!(fmt1("f3aa", m), "2:rep stosb\tbyte ptr [rdi], al");
    assert_eq!(fmt1("c3", m), "1:ret\t");
    assert_eq!(fmt1("e800000000", m), "5:call\t0x1005");
}

#[test]
fn disasm_format_capstone() {
    let s = format_capstone(&[0x55, 0x48, 0x89, 0xe5, 0xc3, 0xff], 0x401000, "intel64");
    assert_eq!(s, "\n0x401000:\tpush\trbp\n0x401001:\tmov\trbp, rsp\n0x401004:\tret\t");
}

#[test]
fn disasm_never_panics_on_random_bytes() {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut buf = [0u8; 64];
    for _ in 0..200_000 {
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        for mode in [Mode::X86_32, Mode::X86_64] {
            for start in 0..4 {
                if let Some(i) = decode(&buf[start..], x, mode) {
                    let _ = i.mnemonic();
                    let _ = i.op_str();
                }
            }
        }
    }
}

/// Differential check against capstone reference corpora produced by
/// `bench/scripts/disasm_diff.py gen` (skipped when testdata/scratch/disasm/ref is absent).
/// Only the first lines of each corpus are checked here to keep `cargo test` fast; run
/// `examples/disasm_diff cmp testdata/scratch/disasm/ref` for the full comparison.
#[test]
fn disasm_matches_capstone_corpora() {
    use std::io::BufRead;
    let dir = std::path::PathBuf::from(crate::util::testdata::path("testdata/scratch/disasm/ref"));
    if !dir.is_dir() {
        eprintln!("disasm corpora not found in {dir:?}; skipping");
        return;
    }
    let unhex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
    };
    let mut bad = Vec::new();
    for name in ["real64", "real32", "rand64", "rand32", "sweep64", "sweep32"] {
        let Ok(f) = std::fs::File::open(dir.join(format!("{name}.ref"))) else { continue };
        let mut insn = Insn::default();
        for line in std::io::BufReader::new(f).lines().take(100_000) {
            let Ok(line) = line else { break };
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() < 7 {
                continue;
            }
            let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
            let addr = u64::from_str_radix(p[2], 16).unwrap_or(0);
            let win = unhex(p[3]);
            let esize: u8 = p[4].parse().unwrap_or(0);
            let ok = x86::decode_into(&win, addr, mode, &mut insn);
            let got = if ok { (insn.size, insn.mnemonic(), insn.op_str()) } else { (0, String::new(), String::new()) };
            let same = got.0 == esize && (esize == 0 || (got.1 == p[5] && got.2 == p[6]));
            if !same && bad.len() < 20 {
                bad.push(format!("{name} {}: exp {esize}:{} {} got {}:{} {}", p[3], p[5], p[6], got.0, got.1, got.2));
            }
        }
    }
    assert!(bad.is_empty(), "mismatches vs capstone:\n{}", bad.join("\n"));
}

#[test]
fn disasm_spec_tables_build() {
    // Spec errors panic in debug builds (tables::build); make sure the tables compile.
    let insn = decode(&[0x90], 0, Mode::X86_64).expect("nop");
    assert_eq!(insn.mnemonic(), "nop");
}
