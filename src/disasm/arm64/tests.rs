//! AArch64 disassembler tests: golden capstone outputs, renderer framing, fuzzing.
//! (The exhaustive 2^32 comparison against capstone lives in bench/scripts/disasm_diff_arm.py.)

use super::*;

fn fmt(word: u32, addr: u64) -> String {
    let mut s = String::new();
    if render_word(word, addr, &mut s) { s } else { "INVALID".into() }
}

#[test]
fn disasm_arm64_golden() {
    let cases: &[(u32, &str)] = &[
        (0xd503201f, "nop\t"),
        (0xa9bf7bfd, "stp\tx29, x30, [sp, #-0x10]!"),
        (0x910003fd, "mov\tx29, sp"),
        (0x94000010, "bl\t#0x1040"),
        (0xd65f03c0, "ret\t"),
        (0xf9400000, "ldr\tx0, [x0]"),
        (0xb9400fe1, "ldr\tw1, [sp, #0xc]"),
        (0xaa0103e0, "mov\tx0, x1"),
        (0xd2800020, "mov\tx0, #1"),
        (0xf2a00020, "movk\tx0, #1, lsl #16"),
        (0x54000041, "b.ne\t#0x1008"),
        (0x17ffffff, "b\t#0xffc"),
        (0x90000000, "adrp\tx0, #0x1000"),
        (0x91002000, "add\tx0, x0, #8"),
        (0xf85f8c20, "ldr\tx0, [x1, #-8]!"),
        (0x38401420, "ldrb\tw0, [x1], #1"),
        (0x9b027c20, "mul\tx0, x1, x2"),
        (0x1e602000, "fcmp\td0, d0"),
        (0x4e208420, "add\tv0.16b, v1.16b, v0.16b"),
        (0x0f000400, "movi\tv0.2s, #0"),
        (0xd5381000, "mrs\tx0, sctlr_el1"),
        (0xd51b4200, "msr\tnzcv, x0"),
        (0xd5087620, "dc\tivac, x0"),
        (0x04a0e3e0, "cntw\tx0"),
        (0x25d8e3e0, "ptrue\tp0.d"),
        (0xd4000001, "svc\t#0"),
    ];
    for &(w, exp) in cases {
        assert_eq!(fmt(w, 0x1000), exp, "word {w:08x}");
    }
}

#[test]
fn disasm_arm64_format_capstone() {
    // stp; mov; invalid word (0xffffffff) stops the listing
    let data = [0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x20, 0x03, 0xd5];
    let mut s = String::new();
    format_arm64_into(&data, 0xffffff8008080000, &mut s);
    assert_eq!(
        s,
        "\n0xffffff8008080000:\tstp\tx29, x30, [sp, #-0x10]!\n0xffffff8008080004:\tmov\tx29, sp"
    );
    // trailing partial word is ignored
    let mut s = String::new();
    format_arm64_into(&[0x1f, 0x20, 0x03, 0xd5, 0x1f], 0, &mut s);
    assert_eq!(s, "\n0x0:\tnop\t");
    let v: Vec<Insn> = disasm(&data, 0x1000).collect();
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].mnemonic(), "mov");
    assert_eq!(v[1].op_str(), "x29, sp");
    assert!(decode(&data[8..], 0).is_none());
}

#[test]
fn disasm_arm64_never_panics() {
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut s = String::new();
    for i in 0..2_000_000u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let addr = if i & 1 == 0 { x.rotate_left(17) } else { x & 0xFFFF };
        s.clear();
        let _ = render_word(x as u32, addr, &mut s);
        s.clear();
        let _ = render_word((x >> 32) as u32, u64::MAX - (x & 0xFFF), &mut s);
    }
    // whole buffers, odd lengths
    let mut buf = vec![0u8; 4099];
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let mut out = String::new();
    format_arm64_into(&buf, u64::MAX - 8, &mut out);
}
