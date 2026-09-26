//! Differential-test driver against yara-python (run by `rules_diff.py` in this
//! directory): reads cases from `$RSVOL_YARA_RULES_CASES`, writes results to
//! `$RSVOL_YARA_RULES_OUT`.
//!
//! Case line: `id \t source_hex \t data_hex`. Result line: `id \t result` with
//! result `ERR:line N: msg` or `OK:` + matches serialized exactly like
//! `rules_diff.py` does for yara-python.
//!
//! String matching uses a naive reference matcher that only supports what the
//! generator emits (plain text strings with optional `nocase` / `wide` /
//! `private`), so the evaluator is tested independently of the real matcher.

use super::{MetaValue, Rules};
use crate::yara::scan::{Match, StringDef, StringKind};

fn unhex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let v = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    };
    b.chunks(2).filter(|c| c.len() == 2).map(|c| v(c[0]) << 4 | v(c[1])).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// All (overlapping) occurrences of a plain text string.
pub fn naive_matches(def: &StringDef, data: &[u8]) -> Vec<Match> {
    let StringKind::Text(t) = &def.kind else {
        return Vec::new();
    };
    let pat: Vec<u8> = if def.mods.wide { t.iter().flat_map(|&c| [c, 0]).collect() } else { t.clone() };
    let mut out = Vec::new();
    if pat.is_empty() || pat.len() > data.len() {
        return out;
    }
    for i in 0..=data.len() - pat.len() {
        let w = &data[i..i + pat.len()];
        let hit = if def.mods.nocase { w.eq_ignore_ascii_case(&pat) } else { w == pat.as_slice() };
        if hit && def.fixed_offset.is_none_or(|o| o == i as i64) {
            out.push(Match { offset: i, len: pat.len(), xor_key: 0 });
        }
    }
    out
}

pub fn serialize(rules: &Rules, data: &[u8]) -> String {
    let ms: Vec<Vec<Match>> = rules.string_defs().iter().map(|d| naive_matches(d, data)).collect();
    let mut parts = Vec::new();
    for m in rules.evaluate(data, &ms) {
        let meta: Vec<String> = m
            .meta
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    MetaValue::Int(i) => i.to_string(),
                    MetaValue::Bool(b) => if *b { "T" } else { "F" }.to_string(),
                    MetaValue::Str(s) => format!("s{}", hex(s)),
                };
                format!("{k}={v}")
            })
            .collect();
        let strs: Vec<String> = m
            .strings
            .iter()
            .map(|s| {
                let inst: Vec<String> = s
                    .instances
                    .iter()
                    .map(|i| format!("{}:{}:{}:{}", i.offset, i.matched_length, hex(&i.matched_data), i.xor_key))
                    .collect();
                format!("{}[{}]", s.identifier, inst.join(","))
            })
            .collect();
        parts.push(format!("{}|{}|{}|{}|{}", m.rule, m.namespace, m.tags.join(","), meta.join(";"), strs.join(";")));
    }
    format!("OK:{}", parts.join(" || "))
}

pub fn run_case(src: &[u8], data: &[u8]) -> String {
    let src = String::from_utf8_lossy(src);
    match Rules::compile(&src) {
        Err(e) => format!("ERR:{e}"),
        Ok(r) => serialize(&r, data),
    }
}

#[test]
#[ignore]
fn yara_rules_difftest_driver() {
    let (Ok(cases), Ok(out)) = (std::env::var("RSVOL_YARA_RULES_CASES"), std::env::var("RSVOL_YARA_RULES_OUT")) else {
        return;
    };
    let text = std::fs::read_to_string(cases).unwrap_or_default();
    let mut res = String::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        let r = run_case(&unhex(f[1]), &unhex(f[2]));
        res.push_str(f[0]);
        res.push('\t');
        res.push_str(&r.replace(['\n', '\t'], " "));
        res.push('\n');
    }
    let _ = std::fs::write(out, res);
}

/// Compile / evaluation timings on a synthetic rule set
/// (`cargo test --profile fast yara_rules_perf -- --ignored --nocapture`).
#[test]
#[ignore]
fn yara_rules_perf() {
    use std::time::Instant;
    let nrules = 2000;
    let mut src = String::new();
    for i in 0..nrules {
        src.push_str(&format!(
            "rule r{i} : tag{} {{ meta: author = \"x\" n = {i} strings: $a = \"abc{i}\" $b = \"def{i}\" nocase \
             $c = \"ghi{i}\" wide $d = \"jkl{i}\" condition: ($a and #b > 2) or (2 of ($c, $d) and @c[1] < 100) \
             or for any i in (1..#a) : (@a[i] + 4 == @b[i]) or uint16(0) == 0x5a4d and filesize < 10MB }}\n",
            i % 7
        ));
    }
    let t = Instant::now();
    let r = Rules::compile(&src).unwrap_or_else(|e| panic!("{e}"));
    let compile = t.elapsed();
    let nstr = r.string_defs().len();
    // Every 10th rule's strings match a few times.
    let data = vec![0u8; 4096];
    let mut ms: Vec<Vec<Match>> = vec![Vec::new(); nstr];
    for (i, v) in ms.iter_mut().enumerate() {
        if (i / 4) % 10 == 0 {
            *v = (0..5).map(|k| Match { offset: k * 16 + (i % 4) * 4, len: 3, xor_key: 0 }).collect();
        }
    }
    let iters = 200;
    let t = Instant::now();
    let mut n = 0;
    for _ in 0..iters {
        n += r.evaluate_rules(&data, &ms).iter().filter(|&&b| b).count();
    }
    let eval = t.elapsed();
    let t = Instant::now();
    for _ in 0..iters {
        n += r.evaluate(&data, &ms).len();
    }
    let full = t.elapsed();
    println!(
        "rules={nrules} strings={nstr} compile={:.2?} ({:.1} us/rule) eval={:.1} us/scan ({:.0} ns/rule) \
         eval+results={:.1} us/scan matched={}",
        compile,
        compile.as_secs_f64() * 1e6 / nrules as f64,
        eval.as_secs_f64() * 1e6 / iters as f64,
        eval.as_secs_f64() * 1e9 / (iters * nrules) as f64,
        full.as_secs_f64() * 1e6 / iters as f64,
        n / (2 * iters)
    );
}
