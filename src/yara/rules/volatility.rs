// Derived from Volatility 3 (Volatility Software License 1.0): the yara-python
// code path of volatility3/framework/plugins/yarascan.py (YaraScanner / YaraScan).
//! volatility3 yarascan glue:
//! * [`get_rule`] = `YaraScanner.get_rule` (yara-python branch);
//! * [`process_yara_options`] = `YaraScan.process_yara_options` for
//!   `yara_string` / `yara_file` (compiled rule files are not supported);
//! * [`scanner_hits`] = `YaraScanner.__call__`: `(offset + data_offset, rule,
//!   string identifier, matched data)` in yara-python iteration order.
//!
//! Users: windows.vadyarascan / linux.vmayarascan (one call per VAD / VMA),
//! yarascan (layer scan chunks), windows.mftscan (`/FILE0|FILE\*|BAAD/` through
//! `process_yara_options`), windows.malware.direct_system_calls (`get_rule` on
//! opcode hex patterns).

use super::{CompileError, Rules};

/// `yara.compile(sources={"n": f"rule r1 {{strings: $a = {rule} condition: $a}}"})`.
pub fn get_rule(pattern: &str) -> Result<Rules, CompileError> {
    let src = format!("rule r1 {{strings: $a = {pattern} condition: $a}}");
    Rules::compile_namespaced(&[("n", &src)])
}

/// `YaraScan.process_yara_options(config)`.
///
/// * `yara_string`: quoted unless it starts with `{` or `/`, then `" nocase"` and
///   `" wide ascii"` are appended per the flags, compiled with [`get_rule`];
/// * else `yara_file_source` (the rule file's bytes): `yara.compile(file=...)`;
/// * else `Ok(None)` (python logs "No yara rules, nor yara rules file were
///   specified" and returns None).
///
/// An empty `yara_string` is an error (python raises IndexError on `rule[0]`).
pub fn process_yara_options(
    yara_string: Option<&str>,
    yara_file_source: Option<&[u8]>,
    insensitive: bool,
    wide: bool,
) -> Result<Option<Rules>, CompileError> {
    if let Some(s) = yara_string {
        let first = match s.chars().next() {
            Some(c) => c,
            None => return Err(CompileError { msg: "string index out of range".into(), line: 0 }),
        };
        let mut rule = if first != '{' && first != '/' { format!("\"{s}\"") } else { s.to_string() };
        if insensitive {
            rule.push_str(" nocase");
        }
        if wide {
            rule.push_str(" wide ascii");
        }
        return get_rule(&rule).map(Some);
    }
    if let Some(src) = yara_file_source {
        return Rules::compile_file_source(src).map(Some);
    }
    Ok(None)
}

/// One `YaraScanner` hit: (absolute offset, rule name, string identifier, data).
pub type Hit = (u64, String, String, Vec<u8>);

/// Hits at `first, first + step, ...` (`count` of them) with the same `tag` (a string index,
/// a matched length): layer scanners report runs, so a pattern matching every byte of a
/// zero page costs 24 bytes per chunk instead of one entry per offset while the hits wait
/// to be rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HitRun {
    pub first: u64,
    pub step: u32,
    pub count: u32,
    pub tag: u64,
}

impl HitRun {
    /// The hit offsets in order.
    pub fn offsets(&self) -> impl Iterator<Item = u64> + use<> {
        let (first, step) = (self.first, self.step as u64);
        (0..self.count as u64).map(move |i| first + i * step)
    }
}

/// Append hit `off` (tag `tag`) to `v`, extending the last run when `off` continues it and the
/// run is at index `base` or later: a scanner passes `hits.len()` from the start of its `scan`
/// call, as the scan framework cuts and reorders the hits of a work item per chunk by index.
#[inline]
pub fn push_run(v: &mut Vec<HitRun>, base: usize, off: u64, tag: u64) {
    if v.len() > base
        && let Some(r) = v.last_mut()
        && r.tag == tag
        && r.count < u32::MAX
        && off > r.first
    {
        let d = off - r.first;
        if r.count == 1 && d <= u32::MAX as u64 {
            r.step = d as u32;
            r.count = 2;
            return;
        }
        if r.step != 0 && d == r.step as u64 * r.count as u64 {
            r.count += 1;
            return;
        }
    }
    v.push(HitRun { first: off, step: 0, count: 1, tag });
}

/// `YaraScanner.__call__(data, data_offset)` (yara-python >= 4.3 branch):
/// `for match in rules.match(data=data): for s in match.strings:
///  for i in s.instances: yield (i.offset + data_offset, match.rule, s.identifier, i.matched_data)`.
pub fn scanner_hits(rules: &Rules, data: &[u8], data_offset: u64) -> Vec<Hit> {
    let mut out = Vec::new();
    for m in rules.scan(data) {
        push_hits(&m, data_offset, &mut out);
    }
    out
}

/// Same as [`scanner_hits`] but from precomputed per-string match lists
/// (see [`Rules::evaluate`]).
pub fn hits_from_matches(
    rules: &Rules,
    data: &[u8],
    data_offset: u64,
    matches: &[Vec<crate::yara::scan::Match>],
) -> Vec<Hit> {
    let mut out = Vec::new();
    for m in rules.evaluate(data, matches) {
        push_hits(&m, data_offset, &mut out);
    }
    out
}

fn push_hits(m: &super::RuleMatch, data_offset: u64, out: &mut Vec<Hit>) {
    for s in &m.strings {
        for i in &s.instances {
            out.push(((i.offset as u64).wrapping_add(data_offset), m.rule.clone(), s.identifier.clone(), i.matched_data.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yara::scan::{Match, StringKind};

    #[test]
    fn hit_runs_round_trip() {
        let hits: Vec<(u64, u64)> = vec![(5, 1), (6, 1), (7, 1), (9, 1), (11, 1), (13, 1), (13, 2), (20, 2), (100, 2), (101, 2), (102, 1), (1 << 40, 1)];
        let mut runs = Vec::new();
        for &(o, t) in &hits {
            push_run(&mut runs, 0, o, t);
        }
        let back: Vec<(u64, u64)> = runs.iter().flat_map(|r| r.offsets().map(move |o| (o, r.tag))).collect();
        assert_eq!(back, hits);
        assert_eq!(runs.len(), 6);
        // a zero page matched at every offset is one run
        let mut runs = Vec::new();
        (0..4096u64).for_each(|o| push_run(&mut runs, 0, 0x1000 + o, 7));
        assert_eq!(runs, vec![HitRun { first: 0x1000, step: 1, count: 4096, tag: 7 }]);
        // a run from before `base` (an earlier chunk of the same work item) is never extended
        push_run(&mut runs, 1, 0x2000, 7);
        assert_eq!(runs.len(), 2);
        push_run(&mut runs, 1, 0x2001, 7);
        assert_eq!(runs[1], HitRun { first: 0x2000, step: 1, count: 2, tag: 7 });
    }

    #[test]
    fn yara_volatility_get_rule_and_options() {
        let r = get_rule("\"MZ\"").unwrap();
        assert_eq!(r.string_defs().len(), 1);
        assert!(matches!(&r.string_defs()[0].kind, StringKind::Text(t) if t == b"MZ"));
        let data = b"xxMZyyMZ";
        let ms = vec![vec![Match { offset: 2, len: 2, xor_key: 0 }, Match { offset: 6, len: 2, xor_key: 0 }]];
        let hits = hits_from_matches(&r, data, 0x1000, &ms);
        assert_eq!(hits, vec![
            (0x1002, "r1".to_string(), "$a".to_string(), b"MZ".to_vec()),
            (0x1006, "r1".to_string(), "$a".to_string(), b"MZ".to_vec())
        ]);
        let ev = r.evaluate(data, &ms);
        assert_eq!(ev[0].namespace, "n");

        let r = process_yara_options(Some("hello"), None, true, true).unwrap().unwrap();
        let m = &r.string_defs()[0].mods;
        assert!(m.nocase && m.wide && m.ascii);
        let r = process_yara_options(Some("{ 4D 5A }"), None, false, false).unwrap().unwrap();
        assert!(matches!(&r.string_defs()[0].kind, StringKind::Hex(h) if h == "{ 4D 5A }"));
        let r = process_yara_options(Some("/FILE0|FILE\\*|BAAD/"), None, false, false).unwrap().unwrap();
        assert!(matches!(&r.string_defs()[0].kind, StringKind::Regex { src, .. } if src == b"FILE0|FILE\\*|BAAD"));
        assert!(process_yara_options(Some(""), None, false, false).is_err());
        assert!(process_yara_options(None, None, false, false).unwrap().is_none());
        let r = process_yara_options(None, Some(b"rule x { condition: true }"), false, false).unwrap().unwrap();
        let ev = r.evaluate(b"", &[]);
        assert_eq!(ev[0].namespace, "default");
        assert!(process_yara_options(Some("a\"b"), None, false, false).is_err());
    }
}
