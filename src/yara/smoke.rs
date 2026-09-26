//! Fast regression tests (`cargo test yara`) against expectations recorded from
//! python `re` and yara-python (see bench/scripts/gen_yara_smoke.py).

use super::regex::Regex;
use super::smoke_cases::{RE_CASES, STR_CASES, YRE_CASES};

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
fn yara_smoke_python_str_re() {
    let mut bad = Vec::new();
    for (i, &(pat, flags, hay, want)) in STR_CASES.iter().enumerate() {
        let got = match Regex::new_str(pat, flags) {
            Err(_) => "ERR".to_string(),
            Ok(re) => re.find_iter(hay.as_bytes()).map(|(s, e)| format!("{s}-{e}")).collect::<Vec<_>>().join(","),
        };
        if got != want {
            bad.push(format!("#{i} {pat:?} flags={flags} hay={hay:?}: want {want} got {got}"));
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
fn yara_smoke_large_counted_repeats() {
    // expectations from python re
    let mut h1 = b"x".to_vec();
    h1.extend(b"ab".repeat(100));
    h1.push(b'a');
    let mut h3 = b"ab".repeat(3000);
    h3.push(b'c');
    let cases: Vec<(&[u8], Vec<u8>, Vec<(usize, usize)>)> = vec![
        (b"(?:ab){2,30000}", h1, vec![(1, 201)]),
        (b"(?:ab){2,30000}?", b"ab".repeat(7), vec![(0, 4), (4, 8), (8, 12)]),
        (b"(?:a|b){5000}c", h3, vec![(1000, 6001)]),
        (b"(?:ab|a){3,20000}b", b"aab".repeat(50), vec![(0, 150)]),
        (b"(?:xy){30000}", b"xy".repeat(29999), vec![]),
    ];
    for (p, h, want) in cases {
        let re = Regex::new(p, 0).unwrap();
        assert_eq!(re.find_iter(&h).collect::<Vec<_>>(), want, "{}", String::from_utf8_lossy(p));
    }
}

#[test]
fn yara_smoke_thread_safety() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Regex>();
    assert_send_sync::<super::scan::re_string::ReString>();
    // concurrent use of one Regex
    let re = Regex::new(br"[a-z]{3}\d", 0).unwrap();
    let hay = b"abc1 xyz9 ".repeat(1000);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| assert_eq!(re.find_iter(&hay).count(), 2000));
        }
    });
}

#[test]
fn yara_smoke_multi_string_pattern() {
    use super::regex::multi_string_pattern;
    // expectations from volatility3's MultiStringScanner._regex
    let cases: &[(&[&[u8]], &[u8])] = &[
        (&[b"Proc", b"File", b"Thre"], b"(?:File|Proc|Thre)"),
        (&[b"ab", b"abc", b"abd", b"x"], b"(?:ab(?:[cd])?|x)"),
        (&[b"a.b", b"a-c", b"a[b"], b"a(?:\\-c|\\.b|\\[b)"),
        (&[b"Linux version ", b"Linux version 5", b"Darwin Kernel"], b"(?:Darwin\\ Kernel|Linux\\ version\\ (?:5)?)"),
    ];
    for (needles, want) in cases {
        let got = multi_string_pattern(needles).unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(want));
        let re = Regex::new(&got, 0).unwrap();
        assert!(re.is_match(needles[0]));
    }
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
