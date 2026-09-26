//! Fast regression tests (`cargo test yara`) against expectations recorded from
//! python `re` and yara-python (see bench/scripts/gen_yara_smoke.py).

use super::regex::Regex;
use super::smoke_cases::{RE_CASES, YRE_CASES};

#[test]
fn yara_smoke_python_re() {
    let mut bad = Vec::new();
    for (i, &(pat, flags, hay, want)) in RE_CASES.iter().enumerate() {
        let got = match Regex::new(pat, flags) {
            Err(_) => "ERR".to_string(),
            Ok(re) => re.find_iter(hay).map(|(s, e)| format!("{s}-{e}")).collect::<Vec<_>>().join(","),
        };
        if got != want {
            bad.push(format!("#{i} {:?} flags={flags} hay={:?}: want {want} got {got}", String::from_utf8_lossy(pat), String::from_utf8_lossy(hay)));
        }
        // The backtracker must agree with python too.
        if let Ok(bt) = Regex::new_backtrack_only(pat, flags) {
            let g2 = bt.find_iter(hay).map(|(s, e)| format!("{s}-{e}")).collect::<Vec<_>>().join(",");
            if g2 != want {
                bad.push(format!("#{i} (backtracker) {:?}: want {want} got {g2}", String::from_utf8_lossy(pat)));
            }
        }
    }
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn yara_smoke_yre_strings() {
    let mut bad = Vec::new();
    for (i, &(kind, src, mods, data, want)) in YRE_CASES.iter().enumerate() {
        let got = super::yre::difftest_run_case(kind, src, mods, data);
        if got != want {
            bad.push(format!("#{i} {kind} {:?} [{mods}]: want {want} got {got}", String::from_utf8_lossy(src)));
        }
    }
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn yara_smoke_regex_basics() {
    let re = Regex::new(br"[a-z]{5,}\.exe", 16).unwrap();
    let hay = b"xx C:\\windows\\explorer.exe and svchost.exe; a.exe";
    let v: Vec<_> = re.find_iter(hay).collect();
    assert_eq!(v, vec![(14, 26), (31, 42)]);
    // python finditer empty-match rules
    let re = Regex::new(b"a*?", 0).unwrap();
    assert_eq!(re.find_iter(b"aa").collect::<Vec<_>>(), vec![(0, 0), (0, 1), (1, 1), (1, 2), (2, 2)]);
    let re = Regex::new(b"(?:|a)*", 0).unwrap();
    assert_eq!(re.match_at(b"aa", 0), Some((0, 0)));
    // errors
    for bad in [&b"a{2,1}"[..], b"(", b"[a-", b"\\q", b"a**", b"(?<=a+)b", b"(?P<1>a)"] {
        assert!(Regex::new(bad, 0).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    // pathological patterns stay polynomial
    let hay = vec![b'a'; 20000];
    let re = Regex::new(b"(a|a)*b", 0).unwrap();
    assert_eq!(re.search(&hay, 0), None);
    let re = Regex::new(b"(a|aa)*(?=c)", 0).unwrap();
    assert_eq!(re.find_iter(&hay).count(), 0);
    let re = Regex::new(b"(a*)*\\1b", 0).unwrap();
    assert_eq!(re.search(&hay[..300], 0), None);
}
