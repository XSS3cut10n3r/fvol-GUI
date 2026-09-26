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
