//! Differential-test driver (run by `bench/scripts/regex_diff.py`):
//! reads cases from `$FASTVOL_REGEX_CASES`, writes results to `$FASTVOL_REGEX_OUT`.
//!
//! Case line: `id \t pattern_hex \t flags \t haystack_hex \t mode` (mode = iter|groups)
//! Result line: `id \t result` where result is `ERR`, `NONE`, spans `s-e,s-e` (iter),
//! or group spans `s-e;s-e;-` (groups). A second column reports the backtracker's
//! answer when it differs from the main engine (`BTDIFF`).

use super::Regex;

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

fn spans(it: impl Iterator<Item = (usize, usize)>) -> String {
    let v: Vec<String> = it.map(|(s, e)| format!("{s}-{e}")).collect();
    v.join(",")
}

pub fn run_case(pat: &[u8], flags: u32, hay: &[u8], mode: &str) -> (String, Option<String>) {
    if mode == "str" {
        // python str pattern; spans reported in bytes of the UTF-8 haystack
        let (Ok(p), Ok(_)) = (std::str::from_utf8(pat), std::str::from_utf8(hay)) else {
            return ("BADUTF8".into(), None);
        };
        return match Regex::new_str(p, flags) {
            Err(_) => ("ERR".into(), None),
            Ok(re) => (spans(re.find_iter(hay)), None),
        };
    }
    let re = match Regex::new(pat, flags) {
        Ok(r) => r,
        Err(_) => return ("ERR".into(), None),
    };
    let bt = Regex::new_backtrack_only(pat, flags).ok();
    match mode {
        "groups" => {
            let fmt = |g: Option<Vec<Option<(usize, usize)>>>| match g {
                None => "NONE".to_string(),
                Some(v) => v
                    .iter()
                    .map(|x| match x {
                        Some((a, b)) => format!("{a}-{b}"),
                        None => "-".into(),
                    })
                    .collect::<Vec<_>>()
                    .join(";"),
            };
            (fmt(re.captures_at(hay, 0)), None)
        }
        _ => {
            let main = spans(re.find_iter(hay));
            let alt = bt.map(|b| spans(b.find_iter(hay)));
            let diff = match alt {
                Some(a) if a != main => Some(a),
                _ => None,
            };
            (main, diff)
        }
    }
}

#[test]
#[ignore]
fn yara_regex_difftest_driver() {
    let Ok(inp) = crate::util::env::var("REGEX_CASES") else { return };
    let out = crate::util::env::var("REGEX_OUT").unwrap_or_else(|_| format!("{inp}.out"));
    let data = std::fs::read_to_string(&inp).expect("read cases");
    let mut res = String::new();
    let trace = crate::util::env::var("REGEX_TRACE").is_ok();
    let mut engines: std::collections::BTreeMap<&'static str, usize> = Default::default();
    for line in data.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            continue;
        }
        if trace {
            eprintln!("case {}", f[0]);
        }
        let flags: u32 = f[2].parse().unwrap_or(0);
        if let Ok(re) = Regex::new(&unhex(f[1]), flags) {
            *engines.entry(re.engine_name()).or_insert(0usize) += 1;
        }
        let (r, d) = run_case(&unhex(f[1]), flags, &unhex(f[3]), f[4]);
        res.push_str(f[0]);
        res.push('\t');
        res.push_str(&r);
        if let Some(d) = d {
            res.push_str("\tBTDIFF:");
            res.push_str(&d);
        }
        res.push('\n');
    }
    std::fs::write(out, res).expect("write results");
    eprintln!("engines: {engines:?}");
}
