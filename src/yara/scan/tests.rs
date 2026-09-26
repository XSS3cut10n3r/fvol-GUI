//! Matcher tests: hand-checked libyara semantics (expected values come from
//! yara-python 4.5.4) and the differential driver used by
//! `bench/scripts/yara_strings_diff.py` (ignored test `yara_scan_difftest`).

use super::*;

fn text(s: &[u8], mods: Modifiers) -> StringDef {
    StringDef { id: "$a".into(), kind: StringKind::Text(s.to_vec()), mods, fixed_offset: None }
}

fn m() -> Modifiers {
    Modifiers::default()
}

fn run(defs: &[StringDef], data: &[u8]) -> Vec<Vec<(usize, usize, u8)>> {
    let mt = Matcher::new(defs).expect("compile");
    let mut out = Vec::new();
    mt.scan(data, &mut out);
    out.iter().map(|v| v.iter().map(|x| (x.offset, x.len, x.xor_key)).collect()).collect()
}

fn one(def: StringDef, data: &[u8]) -> Vec<(usize, usize, u8)> {
    run(&[def], data).pop().unwrap_or_default()
}

#[test]
fn yara_scan_ascii_overlapping() {
    assert_eq!(one(text(b"aa", m()), b"aaaa"), vec![(0, 2, 0), (1, 2, 0), (2, 2, 0)]);
    assert_eq!(one(text(b"abcdefgh", m()), b"xxabcdefghabcdefgh"), vec![(2, 8, 0), (10, 8, 0)]);
    assert_eq!(one(text(b"q", m()), b"qq"), vec![(0, 1, 0), (1, 1, 0)]);
    assert_eq!(one(text(b"abc", m()), b""), vec![]);
    assert_eq!(one(text(b"abc", m()), b"ab"), vec![]);
}

#[test]
fn yara_scan_wide_ascii_fullword() {
    let mods = Modifiers { ascii: true, wide: true, fullword: true, ..m() };
    // yara-python: [(1, 4), (6, 2), (16, 2)]
    assert_eq!(one(text(b"ab", mods.clone()), b"xa\x00b\x00 ab a\x00b\x00c\x00 ab."), vec![(1, 4, 0), (6, 2, 0), (16, 2, 0)]);
    // yara-python: [(1, 6), (8, 3), (21, 3)]
    assert_eq!(
        one(text(b"abc", mods), b"xa\x00b\x00c\x00 abc a\x00b\x00c\x00c\x00 abc."),
        vec![(1, 6, 0), (8, 3, 0), (21, 3, 0)]
    );
}

#[test]
fn yara_scan_fits_in_atom_zero_strings() {
    let mods = Modifiers { ascii: true, wide: true, ..m() };
    assert_eq!(one(text(b"a\x00", mods.clone()), b"a\x00\x00\x00a\x00"), vec![(0, 2, 0), (4, 2, 0)]);
    assert_eq!(one(text(b"a\x00\x00", mods), b"a\x00\x00\x00\x00\x00"), vec![(0, 3, 0)]);
}

#[test]
fn yara_scan_xor() {
    let w: Vec<u8> = "abcdef".encode_utf16().flat_map(|c| c.to_le_bytes()).map(|b| b ^ 5).collect();
    let mut d = b"..".to_vec();
    d.extend_from_slice(&w);
    d.extend_from_slice(b"..");
    let mods = Modifiers { wide: true, xor: Some((0, 255)), ..m() };
    assert_eq!(one(text(b"abcdef", mods), &d), vec![(2, 12, 5)]);
    d.extend(b"abcdef".iter().map(|b| b ^ 6));
    let mods = Modifiers { wide: true, ascii: true, xor: Some((1, 7)), ..m() };
    assert_eq!(one(text(b"abcdef", mods.clone()), &d), vec![(2, 12, 5), (16, 6, 6)]);
    // Key outside the range.
    let mods = Modifiers { wide: true, ascii: true, xor: Some((7, 9)), ..m() };
    assert_eq!(one(text(b"abcdef", mods), &d), vec![]);
    // Plain occurrence reported with key 0 when 0 is in range, not otherwise.
    let mods = Modifiers { xor: Some((0, 3)), ..m() };
    assert_eq!(one(text(b"hello", mods), b"hello"), vec![(0, 5, 0)]);
    let mods = Modifiers { xor: Some((1, 255)), ..m() };
    assert_eq!(one(text(b"hello", mods), b"hello"), vec![]);
    // Short xor string (fits in an atom), every key.
    let mods = Modifiers { xor: Some((0, 255)), ..m() };
    assert_eq!(one(text(b"ab", mods), b"\x03\x00"), vec![(0, 2, 0x62)]);
    let mods = Modifiers { xor: Some((0, 255)), ..m() };
    assert_eq!(one(text(b"a", mods), b"xy"), vec![(0, 1, b'x' ^ b'a'), (1, 1, b'y' ^ b'a')]);
}

#[test]
fn yara_scan_nocase() {
    let mods = Modifiers { nocase: true, ..m() };
    assert_eq!(one(text(b"Hello", mods.clone()), b"hELLO hello HeLlO hell0"), vec![(0, 5, 0), (6, 5, 0), (12, 5, 0)]);
    let mods = Modifiers { nocase: true, wide: true, ..m() };
    assert_eq!(one(text(b"Hi!", mods), b"h\x00I\x00!\x00 hi!"), vec![(0, 6, 0)]);
}

#[test]
fn yara_scan_base64() {
    // yara-python: [(2, 10, 0, b'dABlAHMAdA')] and with ascii also (16, 5, b'dGVzd').
    let mut d = b"xx".to_vec();
    d.extend_from_slice(b"dABlAHMAdAA=");
    d.extend_from_slice(b"yy");
    d.extend_from_slice(b"dGVzdA==");
    let mods = Modifiers { wide: true, base64: Some(None), ..m() };
    assert_eq!(one(text(b"test", mods), &d), vec![(2, 10, 0)]);
    let mods = Modifiers { wide: true, ascii: true, base64: Some(None), ..m() };
    assert_eq!(one(text(b"test", mods), &d), vec![(2, 10, 0), (16, 5, 0)]);
    let mut d = b"xx".to_vec();
    for c in b"dGVzdA==" {
        d.push(*c);
        d.push(0);
    }
    let mods = Modifiers { base64wide: Some(None), ..m() };
    assert_eq!(one(text(b"test", mods), &d), vec![(2, 10, 0)]);
}

#[test]
fn yara_scan_fixed_offset() {
    let mut d = text(b"ab", m());
    d.fixed_offset = Some(2);
    assert_eq!(one(d.clone(), b"ababab"), vec![(2, 2, 0)]);
    d.fixed_offset = Some(1);
    assert_eq!(one(d.clone(), b"ababab"), vec![]);
    d.fixed_offset = Some(-1);
    assert_eq!(one(d.clone(), b"ababab"), vec![]);
    d.fixed_offset = Some(1 << 40);
    assert_eq!(one(d, b"ababab"), vec![]);
}

#[test]
fn yara_scan_invalid_modifiers() {
    assert!(Matcher::new(&[text(b"a", Modifiers { nocase: true, xor: Some((0, 255)), ..m() })]).is_err());
    assert!(Matcher::new(&[text(b"a", Modifiers { nocase: true, base64: Some(None), ..m() })]).is_err());
    assert!(Matcher::new(&[text(b"a", Modifiers { fullword: true, base64wide: Some(None), ..m() })]).is_err());
    assert!(Matcher::new(&[text(b"a", Modifiers { base64: Some(Some(b"abc".to_vec())), ..m() })]).is_err());
    assert!(Matcher::new(&[text(b"", m())]).is_err());
    assert!(Matcher::new(&[text(b"a", Modifiers { xor: Some((5, 4)), ..m() })]).is_err());
}

/// Many strings: exercises both engines and multi-bucket Teddy against a naive scan.
#[test]
fn yara_scan_many_strings_vs_naive() {
    let mut x = 0x0123_4567_89ab_cdefu64;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for &count in &[1usize, 5, 20, 70, 150] {
        let words: Vec<Vec<u8>> = (0..count)
            .map(|_| (0..1 + rnd() % 9).map(|_| b"abcdXYZ\x00\x01 "[(rnd() % 10) as usize]).collect())
            .collect();
        let defs: Vec<StringDef> = words.iter().map(|w| text(w, m())).collect();
        let mut data: Vec<u8> = (0..20000).map(|_| b"abcdXYZ\x00\x01 -"[(rnd() % 11) as usize]).collect();
        for w in &words {
            let p = (rnd() % 19000) as usize;
            data[p..p + w.len()].copy_from_slice(w);
        }
        let got = run(&defs, &data);
        for (i, w) in words.iter().enumerate() {
            let exp: Vec<(usize, usize, u8)> =
                (0..data.len()).filter(|&p| data[p..].starts_with(w)).map(|p| (p, w.len(), 0)).collect();
            assert_eq!(got[i], exp, "count {count} string {i} {:?}", w);
        }
    }
}

#[test]
fn yara_scan_match_cap() {
    // yara-python keeps the first 1_000_000 matches (last offset 1999998).
    let data = b"ab".repeat(1_200_000);
    let got = run(&[text(b"ab", m()), text(b"b", m())], &data);
    assert_eq!(got[0].len(), MAX_STRING_MATCHES);
    assert_eq!(got[0].last().map(|x| x.0), Some(1_999_998));
    assert_eq!(got[1].len(), MAX_STRING_MATCHES);
    assert_eq!(got[1].last().map(|x| x.0), Some(1_999_999));
}

// ---------------------------------------------------------------------------------------
// Differential driver
// ---------------------------------------------------------------------------------------

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

/// `text_hex|mods|alphabet_hex` with mods letters a w n f p b B and `x<lo>-<hi>`.
fn parse_def(spec: &str, idx: usize) -> StringDef {
    let mut parts = spec.split('|');
    let s = unhex(parts.next().unwrap_or(""));
    let mods_s = parts.next().unwrap_or("");
    let alpha = parts.next().filter(|a| !a.is_empty()).map(unhex);
    let mut mods = Modifiers::default();
    let mut it = mods_s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        match c {
            'a' => mods.ascii = true,
            'w' => mods.wide = true,
            'n' => mods.nocase = true,
            'f' => mods.fullword = true,
            'p' => mods.private = true,
            'b' => mods.base64 = Some(alpha.clone()),
            'B' => mods.base64wide = Some(alpha.clone()),
            'x' => {
                let rest = &mods_s[i + 1..];
                let end = rest.find(|c: char| !(c.is_ascii_digit() || c == '-')).unwrap_or(rest.len());
                let (lo, hi) = rest[..end].split_once('-').unwrap_or(("0", "255"));
                mods.xor = Some((lo.parse().unwrap_or(0), hi.parse().unwrap_or(255)));
                for _ in 0..end {
                    it.next();
                }
            }
            _ => {}
        }
    }
    StringDef { id: format!("$s{idx}"), kind: StringKind::Text(s), mods, fixed_offset: None }
}

fn load_data(spec: &str) -> Vec<u8> {
    if let Some(rest) = spec.strip_prefix('@') {
        // @path:offset:len
        let mut it = rest.rsplitn(3, ':');
        let len: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let off: u64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let path = it.next().unwrap_or("");
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(path).expect("open data file");
        f.seek(SeekFrom::Start(off)).expect("seek");
        let mut v = vec![0u8; len];
        f.read_exact(&mut v).expect("read");
        v
    } else {
        unhex(spec)
    }
}

/// Cases from `$RSVOL_YARA_CASES` (`id \t strings(;) \t data \t expected`), results to
/// `$RSVOL_YARA_OUT`: `id \t OK` or `id \t DIFF \t got`.
#[test]
#[ignore]
fn yara_scan_difftest() {
    let Ok(cases) = std::env::var("RSVOL_YARA_CASES") else { return };
    let outp = std::env::var("RSVOL_YARA_OUT").unwrap_or_else(|_| "/dev/stdout".into());
    let text_in = std::fs::read_to_string(cases).expect("cases");
    let mut res = String::new();
    let (mut ok, mut bad) = (0, 0);
    for line in text_in.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 {
            continue;
        }
        let defs: Vec<StringDef> = f[1].split(';').enumerate().map(|(i, s)| parse_def(s, i)).collect();
        let data = load_data(f[2]);
        let got = match Matcher::new(&defs) {
            Err(e) => format!("ERR {e}"),
            Ok(mt) => {
                let mut out = Vec::new();
                mt.scan(&data, &mut out);
                let mut parts = Vec::new();
                for (i, v) in out.iter().enumerate() {
                    if v.is_empty() {
                        continue;
                    }
                    let ms: Vec<String> = v.iter().map(|x| format!("{},{},{}", x.offset, x.len, x.xor_key)).collect();
                    parts.push(format!("{i}:{}", ms.join(" ")));
                }
                parts.join(";")
            }
        };
        let exp = f[3];
        if got == exp || (exp.starts_with("ERR") && got.starts_with("ERR")) {
            ok += 1;
            res.push_str(&format!("{}\tOK\n", f[0]));
        } else {
            bad += 1;
            res.push_str(&format!("{}\tDIFF\t{}\n", f[0], got));
        }
    }
    std::fs::write(outp, res).expect("write results");
    eprintln!("yara difftest: {ok} ok, {bad} diff");
}
