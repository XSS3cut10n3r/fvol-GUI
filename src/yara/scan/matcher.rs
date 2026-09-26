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

use super::freq;
use super::hashf::HashFilter;
use super::literal::{self, TextStr, eq_at};
use super::re_string::{ReState, ReString};
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
    /// Quick window test at the candidate position (4-byte windows only):
    /// `(word | wfold) & wmask == wval`; `wmask == 0` disables it.
    wval: u32,
    wfold: u32,
    wmask: u32,
}

impl Pat {
    fn new(string: u32, sub: u32, off: usize, pat: &[u8], fold: &[u8], w: usize, wlen: usize) -> Pat {
        let (mut wval, mut wfold, mut wmask) = (0, 0, 0);
        if wlen == 4 {
            let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            wval = le(&pat[w..w + 4]);
            wfold = le(&fold[w..w + 4]);
            wmask = u32::MAX;
        }
        Pat {
            string,
            sub,
            off: off as u32,
            len: pat.len() as u32,
            w: w as u32,
            wlen: wlen as u32,
            wval,
            wfold,
            wmask,
        }
    }

    /// Cheap rejection of engine false positives: the window bytes at `q`.
    #[inline(always)]
    fn window_ok(&self, data: &[u8], q: usize) -> bool {
        match data.get(q..q + 4) {
            Some(b) => (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) | self.wfold) & self.wmask == self.wval,
            None => true,
        }
    }
}

/// Candidate search engine over one byte domain.
enum Engine {
    None,
    Teddy(Teddy),
    /// Aho-Corasick over exact window atoms; `map[atom] = pattern`.
    Aho { ac: AhoCorasick, map: Vec<u32> },
    /// Large sets: hashed 4-byte windows, plus an engine for the shorter windows.
    Hash { hf: HashFilter, short: Box<Engine> },
}

/// A pending hex/regex atom hit (processed in libyara's Aho-Corasick order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReHit {
    end: usize,
    /// `u32::MAX - atom length`: longer atoms first at the same end.
    rlen: u32,
    string: u32,
    /// `u32::MAX - atom index`: identical atoms in descending index order.
    ratom: u32,
    pos: usize,
}

/// Reusable scan state (one per thread; tied to the last matcher it was used with).
#[derive(Default)]
pub struct Scratch {
    matcher: u64,
    disabled: Vec<bool>,
    over: Vec<bool>,
    any_over: bool,
    dbuf: Vec<u8>,
    tmp: Vec<Match>,
    re_states: Vec<Option<ReState>>,
    re_hits: Vec<ReHit>,
}

impl Scratch {
    pub fn new() -> Scratch {
        Scratch::default()
    }
}

static MATCHER_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Compiled matcher for a list of strings (all strings of all rules, global index).
pub struct Matcher {
    id: u64,
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
    /// Hex/regex atoms with no bytes: verify at every offset (string, atom), in
    /// libyara order (descending atom index within a string).
    every: Vec<(u32, u32)>,
    /// Any hex/regex strings?
    has_re: bool,
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

/// Rarest window of at most 4 bytes: (offset, length). Raw-domain windows are rated
/// with the byte-pair statistics of real memory (`markov`), difference-stream windows
/// with single-byte frequencies.
fn best_window(pat: &[u8], fold: &[u8], markov: bool) -> (usize, usize) {
    let m = pat.len();
    let wl = m.min(teddy::MAX_WINDOW);
    let mut best = f64::MAX;
    let mut bw = 0;
    for w in 0..=(m - wl) {
        let c = if markov {
            freq::window_prob(&pat[w..w + wl], &fold[w..w + wl])
        } else {
            (0..wl).map(|j| freq(pat[w + j], fold[w + j] != 0)).product()
        };
        if c < best {
            best = c;
            bw = w;
        }
    }
    (bw, wl)
}

fn build_re(def: &StringDef) -> Result<ReString, String> {
    match &def.kind {
        StringKind::Hex(src) => ReString::new_hex(src, &def.mods, def.fixed_offset),
        StringKind::Regex { src, nocase, dotall } => {
            ReString::new_regex(src, *nocase, *dotall, &def.mods, def.fixed_offset)
        }
        StringKind::Text(_) => Err("not a hex/regex string".into()),
    }
}

impl Engine {
    /// Engine for patterns `ids` (indices into `pats`).
    fn build(pats: &[Pat], ids: &[u32], bytes: &[u8], folds: &[u8]) -> Engine {
        if ids.is_empty() {
            return Engine::None;
        }
        // Window byte `j` of pattern `p` and its case-folded alternative, if any.
        let wbyte = |p: &Pat, j: usize| -> (u8, Option<u8>) {
            let a = (p.off + p.w) as usize + j;
            (bytes[a], if folds[a] != 0 { Some(bytes[a] ^ 0x20) } else { None })
        };
        if ids.len() <= TEDDY_MAX {
            let wins: Vec<Vec<ByteSet>> = ids
                .iter()
                .map(|&id| {
                    let p = &pats[id as usize];
                    (0..p.wlen as usize)
                        .map(|j| {
                            let (b, alt) = wbyte(p, j);
                            let mut s = ByteSet::single(b);
                            if let Some(c) = alt {
                                s.insert(c);
                            }
                            s
                        })
                        .collect()
                })
                .collect();
            return Engine::Teddy(Teddy::new(&wins, ids));
        }
        // Exact windows with every case combination of folded letters.
        let expand = |p: &Pat| -> Vec<Vec<u8>> {
            let mut out = vec![Vec::with_capacity(p.wlen as usize)];
            for j in 0..p.wlen as usize {
                let (b, alt) = wbyte(p, j);
                match alt {
                    None => out.iter_mut().for_each(|v| v.push(b)),
                    Some(c) => {
                        let mut more = out.clone();
                        out.iter_mut().for_each(|v| v.push(b));
                        more.iter_mut().for_each(|v| v.push(c));
                        out.extend(more);
                    }
                }
            }
            out
        };
        let (long, short): (Vec<u32>, Vec<u32>) =
            ids.iter().partition(|&&id| pats[id as usize].wlen as usize == teddy::MAX_WINDOW);
        if !long.is_empty() {
            let mut wins = Vec::new();
            let mut wids = Vec::new();
            for &id in &long {
                for w in expand(&pats[id as usize]) {
                    let mut a = [0u8; 4];
                    a.copy_from_slice(&w[..4]);
                    wins.push(a);
                    wids.push(id);
                }
            }
            let short = Box::new(Engine::build(pats, &short, bytes, folds));
            return Engine::Hash { hf: HashFilter::new(&wins, &wids), short };
        }
        let mut atoms: Vec<Vec<u8>> = Vec::new();
        let mut map = Vec::new();
        for &id in ids {
            for w in expand(&pats[id as usize]) {
                atoms.push(w);
                map.push(id);
            }
        }
        Engine::Aho { ac: AhoCorasick::new(&atoms), map }
    }

    fn is_none(&self) -> bool {
        matches!(self, Engine::None)
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
            Engine::Hash { hf, short } => {
                hf.find(hay, from, to, &mut f);
                short.run(hay, from, to, state, f);
            }
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
            id: MATCHER_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            kinds: Vec::with_capacity(strings.len()),
            fixed: Vec::new(),
            pats: Vec::new(),
            bytes: Vec::new(),
            folds: Vec::new(),
            raw: Engine::None,
            dpats: Vec::new(),
            diff: Engine::None,
            every: Vec::new(),
            has_re: false,
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
                            let (w, wl) = best_window(&d, &zero, false);
                            m.dpats.push(Pat::new(si, ci as u32, dbytes.len(), &d, &zero, w, wl));
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
                    m.has_re = true;
                    for (k, a) in rs.atoms().iter().enumerate().rev() {
                        if a.bytes.is_empty() {
                            m.every.push((si, k as u32));
                        }
                    }
                    for (k, a) in rs.atoms().iter().enumerate() {
                        if a.bytes.is_empty() {
                            continue;
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
        let ids: Vec<u32> = (0..m.pats.len() as u32).collect();
        m.raw = Engine::build(&m.pats, &ids, &m.bytes, &m.folds);
        let dzero = vec![0u8; dbytes.len()];
        let ids: Vec<u32> = (0..m.dpats.len() as u32).collect();
        m.diff = Engine::build(&m.dpats, &ids, &dbytes, &dzero);
        Ok(m)
    }

    fn add_pat(&mut self, string: u32, sub: u32, pat: &[u8], fold: &[u8]) {
        let (w, wl) = best_window(pat, fold, true);
        self.pats.push(Pat::new(string, sub, self.bytes.len(), pat, fold, w, wl));
        self.bytes.extend_from_slice(pat);
        self.folds.extend_from_slice(fold);
    }

    /// Diagnostics: engine kinds and the number of candidates each produces on `data`.
    #[cfg(test)]
    pub(crate) fn candidate_stats(&self, data: &[u8]) -> String {
        fn kind(e: &Engine) -> String {
            match e {
                Engine::None => "none".into(),
                Engine::Teddy(t) => format!("teddy(est {:.2e})", t.estimated_rate()),
                Engine::Aho { ac, .. } => format!("aho({} states)", ac.state_count()),
                Engine::Hash { short, .. } => format!("hash+{}", kind(short)),
            }
        }
        let mut st = 0u32;
        let mut raw = 0usize;
        let mut verified = 0usize;
        let mut per = vec![0usize; self.pats.len()];
        self.raw.run(data, 0, data.len(), &mut st, |q, p| {
            raw += 1;
            per[p as usize] += 1;
            let pat = &self.pats[p as usize];
            if let Some(s) = q.checked_sub(pat.w as usize) {
                let (a, e) = (pat.off as usize, (pat.off + pat.len) as usize);
                if eq_at(data, s, &self.bytes[a..e], &self.folds[a..e], 0) {
                    verified += 1;
                }
            }
        });
        let mut top: Vec<(usize, usize)> = per.iter().copied().enumerate().filter(|x| x.1 > 0).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        let top: Vec<String> = top
            .iter()
            .take(8)
            .map(|&(p, c)| {
                let pt = &self.pats[p];
                let a = (pt.off + pt.w) as usize;
                format!("{:?}:{c}", String::from_utf8_lossy(&self.bytes[a..a + pt.wlen as usize]))
            })
            .collect();
        format!(
            "top windows {}\nraw: {} pats, {}, {} candidates, {} verified; diff: {} pats, {}",
            top.join(" "),
            self.pats.len(),
            kind(&self.raw),
            raw,
            verified,
            self.dpats.len(),
            kind(&self.diff)
        )
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
        sc.re_hits.clear();
        if self.has_re {
            if sc.matcher != self.id || sc.re_states.len() != ns {
                sc.re_states = self
                    .kinds
                    .iter()
                    .map(|k| match k {
                        Kind::Re(rs) => Some(rs.new_state()),
                        Kind::Text(_) => None,
                    })
                    .collect();
            } else {
                for st in sc.re_states.iter_mut().flatten() {
                    st.reset();
                }
            }
        }
        sc.matcher = self.id;
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
            if !self.diff.is_none() && n >= 2 {
                // D[i] = data[i] ^ data[i+1] for i in [b0, e).
                let e = (b1 + 64).min(n - 1);
                if e > b0 {
                    dbuf.clear();
                    dbuf.extend(data[b0..e].iter().zip(&data[b0 + 1..e + 1]).map(|(a, b)| a ^ b));
                    let to = b1.min(e) - b0;
                    self.diff.run(&dbuf, 0, to, &mut diff_state, |q, p| self.on_diff(data, b0 + q, p, out, sc));
                }
            }
            if self.has_re {
                self.flush_re(data, b0, b1, b1 == n, out, sc);
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
        if !pat.window_ok(data, q) {
            return;
        }
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
            Kind::Re(_) => sc.re_hits.push(ReHit {
                end: s + pat.len as usize,
                rlen: u32::MAX - pat.len,
                string: pat.string,
                ratom: u32::MAX - pat.sub,
                pos: s,
            }),
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

    /// Processes the pending hex/regex hits that end at or before `b1` (all when
    /// `last`) in libyara order, interleaved with the zero-length atoms at every
    /// position of `[b0, b1)`. Hits of later blocks always end after `b1`.
    fn flush_re(&self, data: &[u8], b0: usize, b1: usize, last: bool, out: &mut [Vec<Match>], sc: &mut Scratch) {
        let mut hits = std::mem::take(&mut sc.re_hits);
        hits.sort_unstable();
        let ready = if last { hits.len() } else { hits.partition_point(|h| h.end <= b1) };
        let mut i = 0;
        if !self.every.is_empty() {
            for p in b0..b1 {
                while i < ready && hits[i].end <= p {
                    let h = hits[i];
                    self.re_hit(data, h.string as usize, (u32::MAX - h.ratom) as usize, h.pos, out, sc);
                    i += 1;
                }
                for &(si, k) in &self.every {
                    if !sc.disabled[si as usize] {
                        self.re_hit(data, si as usize, k as usize, p, out, sc);
                    }
                }
            }
        }
        while i < ready {
            let h = hits[i];
            self.re_hit(data, h.string as usize, (u32::MAX - h.ratom) as usize, h.pos, out, sc);
            i += 1;
        }
        hits.drain(..ready);
        sc.re_hits = hits;
    }

    #[inline]
    fn re_hit(&self, data: &[u8], si: usize, atom: usize, pos: usize, out: &mut [Vec<Match>], sc: &mut Scratch) {
        if sc.disabled[si] {
            return;
        }
        let (Some(Kind::Re(rs)), Some(Some(st))) = (self.kinds.get(si), sc.re_states.get_mut(si)) else {
            return;
        };
        let mut tmp = std::mem::take(&mut sc.tmp);
        tmp.clear();
        rs.verify(st, data, atom, pos, &mut tmp);
        let greedy = rs.greedy();
        for m in tmp.iter() {
            if m.offset >= data.len() || m.len > data.len() - m.offset {
                continue;
            }
            let v = &mut out[si];
            // libyara: a full list disables the string (even for a duplicate offset).
            if v.len() >= MAX_STRING_MATCHES {
                sc.disabled[si] = true;
                break;
            }
            insert_match(v, *m, greedy);
        }
        sc.tmp = tmp;
    }
}
