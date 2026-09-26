//! Differential tester for the capstone *detail mode* API of src/disasm (regs_access, detail
//! operands, opcode bytes) against the reference written by bench/scripts/disasm_detail_diff.py.
//!
//!   cargo run --profile fast --example disasm_detail_diff -- cmp /tmp/rsvol-disasm [--only real64] [--show N]
//!   cargo run --profile fast --example disasm_detail_diff -- bench /tmp/rsvol-disasm/real64.det
//!
//! `cmp` reads DIR/NAME.det, decodes each window with our decoder and compares, per category,
//! against capstone:
//!   opcode    capstone_opcode() bytes            zero      opcode_all_zero() (plugin test)
//!   ops       detail operands without access     opsacc    detail operands incl. access
//!   implR/W   implicit regs_read / regs_write (ordered)
//!   accR/W    regs_access() lists (ordered)      accset    regs_access() as sets
//!   w_eax     "eax"/"rax" in regs_written        w_r10     "r10" in regs_written (plugin tests)
//!   riprel    mov/lea operands[1] RIP-relative target (skeleton_key_check)
//! Rates are printed per corpus (unique lines and occurrence weighted); the most frequent
//! mismatches are shown grouped by (category, mnemonic) and all are written to DIR/NAME.dmis.

#[allow(dead_code, unused_imports)]
#[path = "../src/disasm/mod.rs"]
mod disasm;

use disasm::x86::{self, Insn, Mode, Operand};
use std::collections::HashMap;
use std::fmt::Write as _;
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

const CATS: [&str; 12] =
    ["opcode", "zero", "ops", "opsacc", "implR", "implW", "accR", "accW", "accset", "w_eax", "w_r10", "riprel"];

fn ops_string(insn: &Insn, with_acc: bool) -> String {
    let mut s = String::new();
    for (k, o) in insn.detail_operands().iter().enumerate() {
        if k > 0 {
            s.push('|');
        }
        let acc = if with_acc { o.access.to_string() } else { "x".to_string() };
        match o.op {
            Operand::Reg(r) => {
                let _ = write!(s, "r,{},{},{}", insn.reg_name(r), o.size, acc);
            }
            Operand::Imm(v) => {
                let _ = write!(s, "i,{},{},{}", v, o.size, acc);
            }
            Operand::Mem(m) => {
                let n = |r: x86::Reg| if r.is_none() { "-" } else { insn.reg_name(r) };
                let _ = write!(
                    s,
                    "m,{},{},{},{},{},{},{}",
                    n(m.segment),
                    n(m.base),
                    n(m.index),
                    m.scale,
                    m.disp,
                    o.size,
                    acc
                );
            }
            Operand::None => s.push('?'),
        }
    }
    s
}

fn norm_cs(capstone_ops: &str, keep_acc: bool) -> String {
    // drop avx_bcast; replace the access field of each operand with "x" unless keep_acc
    let mut out = String::new();
    for (k, o) in capstone_ops.split('|').enumerate() {
        if o.is_empty() {
            continue;
        }
        if k > 0 {
            out.push('|');
        }
        let f: Vec<&str> = o.split(',').collect();
        let acc_idx = if f[0] == "m" { 7 } else { 3 };
        for (j, x) in f.iter().enumerate().take(8) {
            if j > 0 {
                out.push(',');
            }
            out.push_str(if j == acc_idx && !keep_acc { "x" } else { x });
        }
    }
    out
}

fn list_string(r: &x86::RegList) -> String {
    r.names().collect::<Vec<_>>().join(",")
}

fn set_of(s: &str) -> Vec<&str> {
    let mut v: Vec<&str> = s.split(',').filter(|x| !x.is_empty()).collect();
    v.sort();
    v.dedup();
    v
}

fn riprel_cs(fields: &[&str], addr: u64, size: u64) -> String {
    // python: operands[1].type == MEM and reg_name(base) == "rip" -> address + size + disp
    let mn = fields[15];
    if mn != "mov" && mn != "lea" {
        return String::new();
    }
    let ops: Vec<&str> = fields[14].split('|').collect();
    match ops.get(1) {
        Some(o) if o.starts_with("m,") => {
            let f: Vec<&str> = o.split(',').collect();
            if f[2] == "rip" {
                let disp: i128 = f[5].parse().unwrap_or(0);
                format!("{}", addr as i128 + size as i128 + disp)
            } else {
                "none".into()
            }
        }
        Some(_) => "none".into(),
        None => "err".into(),
    }
}

fn riprel_ours(insn: &Insn) -> String {
    if !(insn.mnemonic_is("mov") || insn.mnemonic_is("lea")) {
        return String::new();
    }
    let ops = insn.detail_operands();
    match ops.get(1) {
        Some(o) => match o.mem() {
            Some(m) if insn.reg_name(m.base) == "rip" => {
                format!("{}", insn.address as i128 + insn.size as i128 + m.disp as i128)
            }
            _ => "none".into(),
        },
        None => "err".into(),
    }
}

struct Stat {
    uniq: [u64; 12],
    wt: [u64; 12],
}

fn cmp(dir: &str, only: Option<Vec<String>>, show: usize, cats: Option<Vec<String>>) {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".det"))
        .map(|n| n.trim_end_matches(".det").to_string())
        .collect();
    names.sort();
    for name in names {
        if let Some(o) = &only {
            if !o.iter().any(|x| x == &name) {
                continue;
            }
        }
        let f = std::fs::File::open(format!("{dir}/{name}.det")).expect("open det");
        let mis = std::fs::File::create(format!("{dir}/{name}.dmis")).expect("create dmis");
        let mut mis = BufWriter::new(mis);
        let mut st = Stat { uniq: [0; 12], wt: [0; 12] };
        let (mut uniq, mut wtot, mut undecoded) = (0u64, 0u64, 0u64);
        let mut groups: HashMap<(usize, String), (u64, u64, String)> = HashMap::new();
        let t0 = Instant::now();
        let mut insn = Insn::default();
        for line in std::io::BufReader::new(f).lines() {
            let line = line.unwrap();
            let p: Vec<&str> = line.split('\t').collect();
            if p.len() < 17 {
                continue;
            }
            let count: u64 = p[0].parse().unwrap_or(1);
            let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
            let addr = u64::from_str_radix(p[2], 16).unwrap_or(0);
            let win = unhex(p[3]);
            uniq += 1;
            wtot += count;
            if !x86::decode_into(&win, addr, mode, &mut insn) {
                undecoded += 1;
                continue;
            }
            let (ar, aw) = insn.regs_access();
            let (ir, iw) = insn.implicit_regs();
            let ours = [
                insn.capstone_opcode().iter().map(|b| format!("{b:02x}")).collect::<String>(),
                insn.opcode_all_zero().to_string(),
                ops_string(&insn, false),
                ops_string(&insn, true),
                list_string(&ir),
                list_string(&iw),
                list_string(&ar),
                list_string(&aw),
                String::new(),
                (aw.contains_name("eax") || aw.contains_name("rax")).to_string(),
                aw.contains_name("r10").to_string(),
                riprel_ours(&insn),
            ];
            let cs_w = set_of(p[13]);
            let theirs = [
                p[5].to_string(),
                (p[5] == "00000000").to_string(),
                norm_cs(p[14], false),
                norm_cs(p[14], true),
                p[10].to_string(),
                p[11].to_string(),
                p[12].to_string(),
                p[13].to_string(),
                String::new(),
                (cs_w.contains(&"eax") || cs_w.contains(&"rax")).to_string(),
                cs_w.contains(&"r10").to_string(),
                riprel_cs(&p, addr, insn.size as u64),
            ];
            let mut bad_any = false;
            for c in 0..12 {
                let bad = if c == 8 {
                    set_of(&ours[6]) != set_of(p[12]) || set_of(&ours[7]) != set_of(p[13])
                } else {
                    ours[c] != theirs[c]
                };
                if bad {
                    bad_any = true;
                    st.uniq[c] += 1;
                    st.wt[c] += count;
                    let (o, t) = if c == 8 {
                        (format!("{} / {}", ours[6], ours[7]), format!("{} / {}", p[12], p[13]))
                    } else {
                        (ours[c].clone(), theirs[c].clone())
                    };
                    let g = groups.entry((c, p[15].to_string())).or_insert((0, 0, String::new()));
                    g.0 += 1;
                    g.1 += count;
                    if g.2.is_empty() {
                        g.2 = format!("{} {} [{}]  {} {}\n        ours {}\n        cs   {}", p[1], p[3], p[4], p[15], p[16], o, t);
                    }
                }
            }
            if bad_any {
                let _ = writeln!(mis, "{line}");
            }
        }
        let dt = t0.elapsed();
        println!(
            "{name}: {uniq} unique ({wtot} weighted), undecoded {undecoded}, {:.2}s",
            dt.as_secs_f64()
        );
        for c in 0..12 {
            println!(
                "  {:8} unique {:>8} ({:.4}%)  weighted {:>10} ({:.5}%)",
                CATS[c],
                st.uniq[c],
                100.0 * st.uniq[c] as f64 / uniq.max(1) as f64,
                st.wt[c],
                100.0 * st.wt[c] as f64 / wtot.max(1) as f64
            );
        }
        let mut gv: Vec<_> = groups.into_iter().collect();
        gv.sort_by(|a, b| (a.0.0, std::cmp::Reverse(a.1.0)).cmp(&(b.0.0, std::cmp::Reverse(b.1.0))));
        let mut shown_per_cat = [0usize; 12];
        for ((c, mn), (u, w, ex)) in gv {
            if shown_per_cat[c] >= show || cats.as_ref().is_some_and(|v| !v.iter().any(|x| x == CATS[c])) {
                continue;
            }
            shown_per_cat[c] += 1;
            println!("  [{}] {mn}: {u} unique / {w} weighted\n      {ex}", CATS[c]);
        }
    }
}

fn bench(path: &str) {
    let f = std::fs::File::open(path).expect("open det");
    let mut wins: Vec<(Mode, u64, Vec<u8>)> = Vec::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.unwrap();
        let p: Vec<&str> = line.split('\t').collect();
        if p.len() < 5 {
            continue;
        }
        let mode = if p[1] == "64" { Mode::X86_64 } else { Mode::X86_32 };
        wins.push((mode, u64::from_str_radix(p[2], 16).unwrap_or(0), unhex(p[3])));
    }
    let mut insn = Insn::default();
    for round in 0..3 {
        let t0 = Instant::now();
        let mut acc = 0usize;
        for (mode, addr, w) in &wins {
            if x86::decode_into(w, *addr, *mode, &mut insn) {
                let (r, wr) = insn.regs_access();
                acc += r.len() + wr.len();
            }
        }
        let dt = t0.elapsed();
        println!(
            "round {round}: {} insns, decode+regs_access {:.1} ns/insn (checksum {acc})",
            wins.len(),
            dt.as_nanos() as f64 / wins.len().max(1) as f64
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut only = None;
    let mut show = 20;
    let mut cats: Option<Vec<String>> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--only" => {
                only = args.get(i + 1).map(|s| s.split(',').map(|x| x.to_string()).collect());
                i += 1;
            }
            "--cat" => {
                cats = args.get(i + 1).map(|s| s.split(',').map(|x| x.to_string()).collect());
                i += 1;
            }
            "--show" => {
                show = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(20);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    match args.get(1).map(|s| s.as_str()) {
        Some("cmp") => cmp(args.get(2).map_or("/tmp/rsvol-disasm", |s| s.as_str()), only, show, cats),
        Some("bench") => bench(args.get(2).expect("path")),
        _ => eprintln!("usage: disasm_detail_diff cmp DIR [--only a,b] [--show N] | bench FILE.det"),
    }
}
