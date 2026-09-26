//! The multi-string matcher: compiles every string into searchable literals (text
//! variants, hex/regex atoms), finds candidates with one SIMD pass per byte domain
//! (Teddy for small sets, Aho-Corasick for large ones), verifies them with libyara's
//! rules and collects one sorted match list per string.
//!
//! Byte domains:
//! * raw data — text variants (ascii / wide / nocase / small-range xor, base64
//!   alternatives) and hex/regex atoms;
//! * the difference stream `D[i] = data[i] ^ data[i+1]` — xor strings with large key
//!   ranges: `D` is invariant under a constant xor key, so one pattern covers all 256
//!   keys (libyara adds 256 atoms per variant instead).
//!
//! Data is processed in L2-sized blocks so every engine pass reads cached memory.

use super::literal::{self, TextStr, eq_at};
use super::re_string::ReString;
use super::teddy::{self, Teddy};
use super::{MAX_STRING_MATCHES, Match, StringDef, StringKind};
use crate::yara::aho::AhoCorasick;
use crate::yara::regex::hir::ByteSet;
use crate::yara::regex::literal::BYTE_FREQ;

/// Block size for multi-pass scanning (all engines run over one block while it is
/// hot in L2). Multiple of 32.
const BLOCK: usize = 128 * 1024;
/// Most patterns handled by the Teddy engine; larger sets use Aho-Corasick.
const TEDDY_MAX: usize = 64;
/// xor strings with at most this many keys are expanded into literal patterns;
/// larger key ranges are searched in the key-invariant difference stream.
const XOR_EXPAND: usize = 4;

/// Per-string compiled form.
enum Kind {
    Text(TextStr),
    Re(ReString),
}

/// A searchable literal: a variant of a text string, or an atom of a hex/regex string.
#[derive(Clone, Copy, Debug)]
struct Pat {
    string: u32,
    /// Check index (text) or atom index (hex/regex).
    sub: u32,
    /// Bytes / fold mask in the arenas.
    off: u32,
    len: u32,
    /// Window (engine fingerprint) offset inside the pattern and its length.
    w: u32,
    wlen: u32,
}

/// Candidate search engine over one byte domain.
enum Engine {
    None,
    Teddy(Teddy),
    /// Aho-Corasick over exact window atoms; `map[atom] = pattern`.
    Aho { ac: AhoCorasick, map: Vec<u32> },
}

/// Reusable scan state (one per thread).
#[derive(Default)]
pub struct Scratch {
    disabled: Vec<bool>,
    over: Vec<bool>,
    any_over: bool,
    dbuf: Vec<u8>,
    tmp: Vec<Match>,
}

impl Scratch {
    pub fn new() -> Scratch {
        Scratch::default()
    }
}

/// Compiled matcher for a list of strings (all strings of all rules, global index).
pub struct Matcher {
    kinds: Vec<Kind>,
    /// Text strings searched only at a fixed offset.
    fixed: Vec<(u32, i64)>,
    /// Raw-domain patterns and engine.
    pats: Vec<Pat>,
    bytes: Vec<u8>,
    folds: Vec<u8>,
    raw: Engine,
    /// Difference-domain patterns (xor strings with large key ranges).
    dpats: Vec<Pat>,
    diff: Engine,
    /// Hex/regex atoms with no bytes: verify at every offset (string, atom).
    every: Vec<(u32, u32)>,
    /// One-byte xor strings with many keys: resolve at every offset.
    every_text: Vec<u32>,
    /// Longest pattern / check span (bounds libyara's discovery-order window).
    max_span: usize,
}

fn freq(b: u8, fold: bool) -> f64 {
    let mut f = BYTE_FREQ[b as usize] as f64;
    if fold {
        f += BYTE_FREQ[(b ^ 0x20) as usize] as f64;
    }
    f
}

/// Rarest window (by memory byte frequency) of at most 4 bytes: (offset, length).
fn best_window(pat: &[u8], fold: &[u8]) -> (usize, usize) {
    let m = pat.len();
    let wl = m.min(teddy::MAX_WINDOW);
    let mut best = f64::MAX;
    let mut bw = 0;
    for w in 0..=(m - wl) {
        let mut c = 1.0;
        for j in 0..wl {
            c *= freq(pat[w + j], fold[w + j] != 0);
        }
        if c < best {
            best = c;
            bw = w;
        }
    }
    (bw, wl)
}

fn build_re(def: &StringDef) -> Result<ReString, String> {
    match &def.kind {
        StringKind::Hex(src) => ReString::new_hex(src, &def.mods),
        StringKind::Regex { src, nocase, dotall } => ReString::new_regex(src, *nocase, *dotall, &def.mods),
        StringKind::Text(_) => Err("not a hex/regex string".into()),
    }
}

impl Engine {
    fn build(pats: &[Pat], bytes: &[u8], folds: &[u8]) -> Engine {
        if pats.is_empty() {
            return Engine::None;
        }
        if pats.len() <= TEDDY_MAX {
            let mut wins = Vec::with_capacity(pats.len());
            for p in pats {
                let a = (p.off + p.w) as usize;
                let win: Vec<ByteSet> = (0..p.wlen as usize)
                    .map(|j| {
                        let b = bytes[a + j];
                        let mut s = ByteSet::single(b);
                        if folds[a + j] != 0 {
                            s.insert(b ^ 0x20);
                        }
                        s
                    })
                    .collect();
                wins.push(win);
            }
            let ids: Vec<u32> = (0..pats.len() as u32).collect();
            return Engine::Teddy(Teddy::new(&wins, &ids));
        }
        let mut atoms: Vec<Vec<u8>> = Vec::new();
        let mut map = Vec::new();
        for (pi, p) in pats.iter().enumerate() {
            let a = (p.off + p.w) as usize;
            let win = &bytes[a..a + p.wlen as usize];
            let fold = &folds[a..a + p.wlen as usize];
            // Case combinations of folded letters.
            let folded: Vec<usize> = (0..win.len()).filter(|&j| fold[j] != 0).collect();
            for combo in 0..(1usize << folded.len()) {
                let mut v = win.to_vec();
                for (bit, &j) in folded.iter().enumerate() {
                    if combo >> bit & 1 != 0 {
                        v[j] ^= 0x20;
                    }
                }
                atoms.push(v);
                map.push(pi as u32);
            }
        }
        Engine::Aho { ac: AhoCorasick::new(&atoms), map }
    }

    /// Candidate windows in `hay[from..to)`: `f(q, pattern)` with `q` the window start.
    #[inline]
    fn run<F: FnMut(usize, u32)>(&self, hay: &[u8], from: usize, to: usize, state: &mut u32, mut f: F) {
        match self {
            Engine::None => {}
            Engine::Teddy(t) => t.find(hay, from, to, f),
            Engine::Aho { ac, map } => ac.scan(hay, from, to, state, |a, end| {
                let len = ac.pattern_len(a);
                if let Some(&p) = map.get(a as usize) {
                    f(end - len, p);
                }
            }),
        }
    }
}

/// Inserts `m` keeping `v` sorted by offset, one match per offset (libyara
/// `_yr_scan_add_match_to_list`: an existing offset is replaced only if `replace`).
#[inline]
fn insert_match(v: &mut Vec<Match>, m: Match, replace: bool) {
    let mut i = v.len();
    while i > 0 {
        let o = v[i - 1].offset;
        if o == m.offset {
            if replace {
                v[i - 1] = m;
            }
            return;
        }
        if m.offset > o {
            break;
        }
        i -= 1;
    }
    if i == v.len() {
        v.push(m);
    } else {
        v.insert(i, m);
    }
}

impl Matcher {
    /// Compile. Errors mirror yara compile errors for invalid hex / regex / modifier
    /// combinations (message text is informative only).
    pub fn new(strings: &[StringDef]) -> Result<Matcher, String> {
        let mut m = Matcher {
            kinds: Vec::with_capacity(strings.len()),
            fixed: Vec::new(),
            pats: Vec::new(),
            bytes: Vec::new(),
            folds: Vec::new(),
            raw: Engine::None,
            dpats: Vec::new(),
            diff: Engine::None,
            every: Vec::new(),
            every_text: Vec::new(),
            max_span: 1,
        };
        let mut dbytes: Vec<u8> = Vec::new();
        for (si, def) in strings.iter().enumerate() {
            let si = si as u32;
            match &def.kind {
                StringKind::Text(s) => {
                    let ts = TextStr::new(s, &def.mods).map_err(|e| format!("{}: {e}", def.id))?;
                    m.max_span = m.max_span.max(ts.max_len);
                    // libyara keeps STRING_FLAGS_FIXED_OFFSET for literal strings only;
                    // base64 strings are regular expressions.
                    if let (Some(off), false) = (def.fixed_offset, ts.base64) {
                        m.fixed.push((si, off));
                        m.kinds.push(Kind::Text(ts));
                        continue;
                    }
                    for (ci, c) in ts.checks.iter().enumerate() {
                        if !c.searched {
                            continue;
                        }
                        if !c.xor {
                            m.add_pat(si, ci as u32, &c.pat, &c.fold);
                            continue;
                        }
                        let (lo, hi) = ts.xor.unwrap_or((0, 0));
                        let nkeys = hi as usize - lo as usize + 1;
                        // Expanding keys is exact only when every libyara candidate
                        // carries a key in range: strings that fit in an atom, or
                        // ascii-only strings (no cross-variant atom hits).
                        let exact = ts.fits || !ts.checks.iter().any(|c| c.wide);
                        if nkeys <= XOR_EXPAND && exact {
                            for k in lo..=hi {
                                let x: Vec<u8> = c.pat.iter().map(|&b| b ^ k).collect();
                                m.add_pat(si, ci as u32, &x, &c.fold);
                            }
                        } else if c.len() >= 2 {
                            let d: Vec<u8> = c.pat.windows(2).map(|w| w[0] ^ w[1]).collect();
                            let zero = vec![0u8; d.len()];
                            let (w, wl) = best_window(&d, &zero);
                            m.dpats.push(Pat {
                                string: si,
                                sub: ci as u32,
                                off: dbytes.len() as u32,
                                len: d.len() as u32,
                                w: w as u32,
                                wlen: wl as u32,
                            });
                            dbytes.extend_from_slice(&d);
                        } else if !m.every_text.contains(&si) {
                            m.every_text.push(si);
                        }
                    }
                    m.kinds.push(Kind::Text(ts));
                }
                StringKind::Hex(_) | StringKind::Regex { .. } => {
                    if def.mods.xor.is_some() || def.mods.base64.is_some() || def.mods.base64wide.is_some() {
                        return Err(format!("{}: invalid modifier for hex/regex string", def.id));
                    }
                    let rs = build_re(def).map_err(|e| format!("{}: {e}", def.id))?;
                    if rs.atoms().is_empty() {
                        m.every.push((si, 0));
                    }
                    for (k, a) in rs.atoms().iter().enumerate() {
                        if a.bytes.is_empty() {
                            m.every.push((si, k as u32));
                        } else {
                            m.max_span = m.max_span.max(a.bytes.len());
                            let zero = vec![0u8; a.bytes.len()];
                            m.add_pat(si, k as u32, &a.bytes, &zero);
                        }
                    }
                    m.kinds.push(Kind::Re(rs));
                }
            }
        }
        m.raw = Engine::build(&m.pats, &m.bytes, &m.folds);
        let dzero = vec![0u8; dbytes.len()];
        m.diff = Engine::build(&m.dpats, &dbytes, &dzero);
        Ok(m)
    }

    fn add_pat(&mut self, string: u32, sub: u32, pat: &[u8], fold: &[u8]) {
        let (w, wl) = best_window(pat, fold);
        self.pats.push(Pat {
            string,
            sub,
            off: self.bytes.len() as u32,
            len: pat.len() as u32,
            w: w as u32,
            wlen: wl as u32,
        });
        self.bytes.extend_from_slice(pat);
        self.folds.extend_from_slice(fold);
    }

    /// Number of strings.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Scan `data`. On return `out.len() == strings.len()` and `out[i]` holds the
    /// matches of string `i`, sorted by offset, one per offset, capped at
    /// [`MAX_STRING_MATCHES`].
    pub fn scan(&self, data: &[u8], out: &mut Vec<Vec<Match>>) {
        let mut sc = Scratch::new();
        self.scan_with(&mut sc, data, out);
    }

    /// [`Matcher::scan`] with caller-owned scratch space (no allocation per call once
    /// warmed up, apart from the match vectors themselves).
    pub fn scan_with(&self, sc: &mut Scratch, data: &[u8], out: &mut Vec<Vec<Match>>) {
        let ns = self.kinds.len();
        out.truncate(ns);
        for v in out.iter_mut() {
            v.clear();
        }
        out.resize(ns, Vec::new());
        sc.disabled.clear();
        sc.disabled.resize(ns, false);
        sc.over.clear();
        sc.over.resize(ns, false);
        sc.any_over = false;
        let n = data.len();
        if n == 0 {
            return;
        }
        for &(si, off) in &self.fixed {
            if off >= 0 && (off as u64) < n as u64 {
                if let Kind::Text(ts) = &self.kinds[si as usize] {
                    if let Some(mt) = ts.resolve(data, off as usize, usize::MAX) {
                        out[si as usize].push(mt);
                    }
                }
            }
        }
        let mut raw_state = 0u32;
        let mut diff_state = 0u32;
        let mut dbuf = std::mem::take(&mut sc.dbuf);
        let mut b0 = 0usize;
        while b0 < n {
            let b1 = (b0 + BLOCK).min(n);
            self.raw.run(data, b0, b1, &mut raw_state, |q, p| self.on_raw(data, q, p, out, sc));
            if !matches!(self.diff, Engine::None) && n >= 2 {
                // D[i] = data[i] ^ data[i+1] for i in [b0, e).
                let e = (b1 + 64).min(n - 1);
                if e > b0 {
                    dbuf.clear();
                    dbuf.extend(data[b0..e].iter().zip(&data[b0 + 1..e + 1]).map(|(a, b)| a ^ b));
                    let to = b1.min(e) - b0;
                    self.diff.run(&dbuf, 0, to, &mut diff_state, |q, p| self.on_diff(data, b0 + q, p, out, sc));
                }
            }
            for &(si, k) in &self.every {
                if let Kind::Re(rs) = &self.kinds[si as usize] {
                    for s in b0..b1 {
                        if sc.disabled[si as usize] {
                            break;
                        }
                        self.re_hit(data, si as usize, rs, k as usize, s, out, sc);
                    }
                }
            }
            for &si in &self.every_text {
                if let Kind::Text(ts) = &self.kinds[si as usize] {
                    for s in b0..b1 {
                        if sc.disabled[si as usize] {
                            break;
                        }
                        if let Some(mt) = ts.resolve(data, s, usize::MAX) {
                            self.add_text(si as usize, mt, out, sc);
                        }
                    }
                }
            }
            if sc.any_over {
                self.check_caps(data, b1, false, out, sc);
            }
            b0 = b1;
        }
        if sc.any_over {
            self.check_caps(data, n, true, out, sc);
        }
        sc.dbuf = dbuf;
    }

    /// Strings over the match cap: once no future candidate can precede the first
    /// `MAX_STRING_MATCHES` (in libyara's discovery order), keep those and stop.
    fn check_caps(&self, data: &[u8], done: usize, last: bool, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let mut any = false;
        for si in 0..self.kinds.len() {
            if !sc.over[si] || sc.disabled[si] {
                continue;
            }
            let v = &mut out[si];
            let ready = last
                || v.len() < MAX_STRING_MATCHES
                || done > v[MAX_STRING_MATCHES - 1].offset.saturating_add(2 * self.max_span + 1);
            if !ready {
                any = true;
                continue;
            }
            if let Kind::Text(ts) = &self.kinds[si] {
                literal::cap_by_discovery(v, |m| ts.discovery(data, m));
            } else {
                v.truncate(MAX_STRING_MATCHES);
            }
            sc.disabled[si] = true;
        }
        sc.any_over = any;
    }

    #[inline]
    fn add_text(&self, si: usize, m: Match, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let v = &mut out[si];
        insert_match(v, m, false);
        if v.len() >= MAX_STRING_MATCHES && !sc.over[si] {
            sc.over[si] = true;
            sc.any_over = true;
        }
    }

    /// Raw-domain candidate: window of pattern `p` at `q`.
    #[inline]
    fn on_raw(&self, data: &[u8], q: usize, p: u32, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let Some(pat) = self.pats.get(p as usize) else { return };
        let Some(s) = q.checked_sub(pat.w as usize) else { return };
        let si = pat.string as usize;
        if sc.disabled[si] {
            return;
        }
        let (a, e) = (pat.off as usize, (pat.off + pat.len) as usize);
        if !eq_at(data, s, &self.bytes[a..e], &self.folds[a..e], 0) {
            return;
        }
        match &self.kinds[si] {
            Kind::Text(ts) => {
                if out[si].last().is_some_and(|m| m.offset == s) {
                    return;
                }
                if let Some(m) = ts.resolve(data, s, pat.sub as usize) {
                    self.add_text(si, m, out, sc);
                }
            }
            Kind::Re(rs) => self.re_hit(data, si, rs, pat.sub as usize, s, out, sc),
        }
    }

    /// Difference-domain candidate (xor strings).
    #[inline]
    fn on_diff(&self, data: &[u8], q: usize, p: u32, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let Some(pat) = self.dpats.get(p as usize) else { return };
        let Some(s) = q.checked_sub(pat.w as usize) else { return };
        let si = pat.string as usize;
        if sc.disabled[si] || s >= data.len() {
            return;
        }
        if let Kind::Text(ts) = &self.kinds[si] {
            if out[si].last().is_some_and(|m| m.offset == s) {
                return;
            }
            let Some(c) = ts.checks.get(pat.sub as usize) else { return };
            let key = data[s] ^ c.pat[0];
            if !c.matches(data, s, key) {
                return;
            }
            if let Some(m) = ts.resolve(data, s, pat.sub as usize) {
                self.add_text(si, m, out, sc);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn re_hit(&self, data: &[u8], si: usize, rs: &ReString, atom: usize, pos: usize, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let mut tmp = std::mem::take(&mut sc.tmp);
        tmp.clear();
        rs.verify(data, atom, pos, &mut tmp);
        let greedy = rs.greedy();
        for m in tmp.iter() {
            if m.offset >= data.len() || m.len > data.len() - m.offset {
                continue;
            }
            let v = &mut out[si];
            if v.len() >= MAX_STRING_MATCHES {
                sc.disabled[si] = true;
                break;
            }
            insert_match(v, *m, greedy);
        }
        sc.tmp = tmp;
    }
}
