//! 32-bit ARM disassembler tests: golden capstone outputs, renderer framing, fuzzing.
//! (The exhaustive 2^32 comparison against capstone lives in bench/scripts/disasm_diff_arm.py.)

use super::*;

fn fmt(word: u32, addr: u64) -> String {
    let mut s = String::new();
    if render_word(word, addr, &mut s) {
        s
    } else {
        "INVALID".into()
    }
}

#[test]
fn disasm_arm_golden() {
    let cases: &[(u32, &str)] = &[
        (0xe0810002, "add\tr0, r1, r2"),
        (0x00810002, "addeq\tr0, r1, r2"),
        (0x00910002, "addseq\tr0, r1, r2"),
        (0x0e300a01, "vaddeq.f32\ts0, s0, s2"),
        (0xe12fff1e, "bx\tlr"),
        (0xebfffffe, "bl\t#0x1000"),
        (0xe92d4010, "push\t{r4, lr}"),
        (0x08bd4010, "popeq\t{r4, lr}"),
        (0xe59f0004, "ldr\tr0, [pc, #4]"),
        (0xe1a0900a, "mov\tsb, sl"),
        (0xe92d0001, "stmdb\tsp!, {r0}"),
        (0xed2d8b04, "vpush\t{d8, d9}"),
        (0xe28f0004, "add\tr0, pc, #4"),
        (0xe7c0001f, "bfc\tr0, #0, #1"),
        (0xe1200070, "bkpt\t#0"),
        (0xf57ff04f, "dsb\tsy"),
        (0xe1a00081, "lsl\tr0, r1, #1"),
        (0xe320f000, "nop\t"),
    ];
    for &(w, exp) in cases {
        assert_eq!(fmt(w, 0x1000), exp, "word {w:08x}");
    }
}

#[test]
fn disasm_arm_format_capstone() {
    // push {r4, lr}; add r0, r1, r2; 0xffffffff is invalid and stops the listing
    let data = [
        0x10, 0x40, 0x2d, 0xe9, 0x02, 0x00, 0x81, 0xe0, 0xff, 0xff, 0xff, 0xff, 0x1e, 0xff, 0x2f,
        0xe1,
    ];
    let mut s = String::new();
    format_arm_into(&data, 0x8000, &mut s);
    assert_eq!(s, "\n0x8000:\tpush\t{r4, lr}\n0x8004:\tadd\tr0, r1, r2");
    let v: Vec<Insn> = disasm(&data, 0x8000).collect();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].mnemonic(), "push");
    assert_eq!(v[0].op_str(), "{r4, lr}");
}

#[test]
fn disasm_arm_never_panics() {
    let mut x: u64 = 0xD1B54A32D192ED03;
    let mut s = String::new();
    for i in 0..2_000_000u64 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let addr = if i & 1 == 0 {
            x.rotate_left(17)
        } else {
            x & 0xFFFF
        };
        s.clear();
        let _ = render_word(x as u32, addr, &mut s);
        s.clear();
        let _ = render_word((x >> 32) as u32, u64::MAX - (x & 0xFFF), &mut s);
    }
    let mut buf = vec![0u8; 4099];
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let mut out = String::new();
    format_arm_into(&buf, u64::MAX - 8, &mut out);
}
