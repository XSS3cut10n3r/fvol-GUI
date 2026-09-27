//! Differential-test driver for YARA hex / regex strings (run by
//! bench/scripts/yre_diff.py): `$FASTVOL_YRE_CASES` -> `$FASTVOL_YRE_OUT`.
//!
//! Case line: `id \t kind(hex|re) \t source_hex \t mods \t data_hex` where mods is a
//! comma list of: nocase, dotall, wide, ascii, fullword.
//! Result line: `id \t ERR` or `id \t off:len,off:len,...`.

use crate::yara::scan::re_string::{scan_reference, ReString};
use crate::yara::scan::Modifiers;

fn unhex(s: &str) -> Vec<u8> {
    let v = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    };
    s.as_bytes().chunks(2).filter(|c| c.len() == 2).map(|c| v(c[0]) << 4 | v(c[1])).collect()
}

pub fn run_case(kind: &str, src: &[u8], mods: &str, data: &[u8]) -> String {
    let has = |m: &str| mods.split(',').any(|x| x == m);
    let m = Modifiers { ascii: has("ascii"), wide: has("wide"), nocase: false, fullword: has("fullword"), ..Default::default() };
    let rs = if kind == "hex" {
        ReString::new_hex(&String::from_utf8_lossy(src), &m, None)
    } else {
        ReString::new_regex(src, has("nocase"), has("dotall"), &m, None)
    };
    match rs {
        Err(_) => "ERR".into(),
        Ok(rs) => {
            let v: Vec<String> = scan_reference(&rs, data).iter().map(|m| format!("{}:{}", m.offset, m.len)).collect();
            v.join(",")
        }
    }
}

#[test]
#[ignore]
fn yara_yre_difftest_driver() {
    let Ok(inp) = crate::util::env::var("YRE_CASES") else { return };
    let out = crate::util::env::var("YRE_OUT").unwrap_or_else(|_| format!("{inp}.out"));
    let data = std::fs::read_to_string(&inp).expect("read cases");
    let trace = crate::util::env::var("YRE_TRACE").is_ok();
    let mut res = String::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            continue;
        }
        if trace {
            eprintln!("case {}", f[0]);
        }
        let r = run_case(f[1], &unhex(f[2]), f[3], &unhex(f[4]));
        res.push_str(f[0]);
        res.push('\t');
        res.push_str(&r);
        res.push('\n');
    }
    std::fs::write(out, res).expect("write results");
}
