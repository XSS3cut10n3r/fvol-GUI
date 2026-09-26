//! Text strings (and base64 alternatives): variant expansion and the exact libyara 4.5
//! verification semantics (scan.c `_yr_scan_verify_literal_match` +
//! `_yr_scan_match_callback`).
//!
//! A text string is compiled into an ordered list of *checks* — one per variant
//! (ascii / wide, plain / nocase / xor) in the order libyara tries them when one of the
//! string's atoms hits. In libyara the verification at a start offset `s` does not
//! depend on which atom triggered it, so the reported match is a function of `s`:
//!
//! * `s` must be a libyara candidate: some atom of the string hits at `s + backtrack`
//!   (for most strings this is implied by the full match of any variant; xor strings
//!   check it explicitly — libyara's atoms carry the key range, its verification
//!   does not, and it even tries the ascii xor form of `wide`-only strings);
//! * the result is the first check (in libyara order) whose bytes match at `s`;
//! * `fullword` rejects the offset when that first match has an alphanumeric
//!   neighbour (the wide variant looks at byte pairs), except for strings that fit in
//!   an atom (<= 4 bytes after widening): those have one atom per variant, recorded
//!   without verification, shortest first, so a rejected ascii match lets the wide
//!   one through;
//! * xor strings: the key is `data[s] ^ string[0]` (a match with key 0 is a plain
//!   match);
//! * base64 strings are a regular-expression alternation of literals: every
//!   alternative has its own atom; the alternative whose atom is reached first by the
//!   scan wins (longer atoms first at the same position, then declaration order).
//!
//! Because the result depends only on `s`, candidates can be produced by any search
//! engine in any order; duplicates are identical.

use super::{MAX_STRING_MATCHES, Match, Modifiers};

const DEFAULT_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// One variant of a string.
#[derive(Clone, Debug)]
pub struct Check {
    /// Bytes to compare: `(data | fold) ^ pat == key` for every byte.
    pub pat: Vec<u8>,
    /// 0x20 at case-insensitive letter positions (letters in `pat` are lowercase).
    pub fold: Vec<u8>,
    /// Match length is `2 * string length` (RE_FLAGS_WIDE for fullword).
    pub wide: bool,
    /// Compare with the key derived from the data (`data[s] ^ pat[0]`).
    pub xor: bool,
    /// Must our engines search for this variant (it can produce a match at an
    /// offset where no other searched variant matches)?
    pub searched: bool,
    /// Does libyara put atoms for this variant into its automaton?
    pub yatom: bool,
    /// libyara's atom for this variant: (backtrack, length) — used to replay
    /// libyara's discovery order when the per-string match cap is reached.
    pub ybt: u32,
    pub ylen: u32,
}

impl Check {
    #[inline]
    pub fn len(&self) -> usize {
        self.pat.len()
    }

    /// Does the variant match at `s` with xor key `key` (0 for non-xor)?
    #[inline]
    pub fn matches(&self, data: &[u8], s: usize, key: u8) -> bool {
        eq_at(data, s, &self.pat, &self.fold, key)
    }

    /// Does libyara's atom of this variant hit at `s + ybt`?
    fn atom_hits(&self, data: &[u8], s: usize, range: Option<(u8, u8)>) -> bool {
        let a = self.ybt as usize;
        let e = a + self.ylen as usize;
        if e > self.pat.len() || e == a {
            return false;
        }
        let p = s + a;
        if p >= data.len() {
            return false;
        }
        let key = if self.xor { data[p] ^ self.pat[a] } else { 0 };
        if let (true, Some((lo, hi))) = (self.xor, range) {
            if key < lo || key > hi {
                return false;
            }
        }
        eq_at(data, p, &self.pat[a..e], &self.fold[a..e], key)
    }
}

#[inline(always)]
fn ld64(b: &[u8], i: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(w)
}

/// `(data[s+i] | fold[i]) ^ pat[i] == key` for all i (false when out of bounds).
#[inline]
pub fn eq_at(data: &[u8], s: usize, pat: &[u8], fold: &[u8], key: u8) -> bool {
    let m = pat.len();
    let d = match s.checked_add(m).and_then(|e| data.get(s..e)) {
        Some(d) => d,
        None => return false,
    };
    let fold = &fold[..m];
    let kk = u64::from_ne_bytes([key; 8]);
    let mut i = 0;
    while i + 8 <= m {
        if (ld64(d, i) | ld64(fold, i)) ^ ld64(pat, i) != kk {
            return false;
        }
        i += 8;
    }
    while i < m {
        if (d[i] | fold[i]) ^ pat[i] != key {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
pub fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// libyara `_yr_scan_match_callback` fullword test.
#[inline]
pub fn fullword_ok(data: &[u8], s: usize, len: usize, wide: bool) -> bool {
    let n = data.len();
    if wide {
        if s >= 2 && data[s - 1] == 0 && is_alnum(data[s - 2]) {
            return false;
        }
        if s + len + 1 < n && data[s + len + 1] == 0 && is_alnum(data[s + len]) {
            return false;
        }
    } else {
        if s >= 1 && is_alnum(data[s - 1]) {
            return false;
        }
        if s + len < n && is_alnum(data[s + len]) {
            return false;
        }
    }
    true
}

/// A compiled text string.
#[derive(Clone, Debug)]
pub struct TextStr {
    pub checks: Vec<Check>,
    /// STRING_FLAGS_FITS_IN_ATOM.
    pub fits: bool,
    pub fullword: bool,
    /// xor key range.
    pub xor: Option<(u8, u8)>,
    /// First byte of the string (key derivation).
    pub first: u8,
    /// base64 alternation (shortest alternative wins).
    pub base64: bool,
    /// Longest check.
    pub max_len: usize,
}

fn widen(s: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(s.len() * 2);
    for &b in s {
        w.push(b);
        w.push(0);
    }
    w
}

/// libyara `yr_atoms_heuristic_quality` for a fully-masked atom.
fn atom_quality(a: &[u8]) -> i32 {
    let mut q = 0i32;
    let mut seen = [false; 256];
    let mut unique = 0;
    for &b in a {
        q += match b {
            0x00 | 0x20 | 0xCC | 0xFF => 12,
            _ if b.is_ascii_alphabetic() => 18,
            _ => 20,
        };
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique += 1;
        }
    }
    if unique == 1 && (seen[0x00] || seen[0x20] || seen[0x90] || seen[0xCC] || seen[0xFF]) {
        q -= 10 * a.len() as i32;
    } else {
        q += 2 * unique;
    }
    255 - 22 * 4 + q
}

/// libyara `yr_atoms_extract_from_string` atom choice: (backtrack, length).
fn yara_atom(s: &[u8]) -> (usize, usize) {
    let alen = s.len().min(4);
    let mut best = atom_quality(&s[..alen]);
    let mut bt = 0;
    let mut len = alen;
    let mut i = 4;
    while i < s.len() && best < 255 {
        let q = atom_quality(&s[i - 3..=i]);
        if q > best {
            best = q;
            bt = i - 3;
            len = 4;
        }
        i += 1;
    }
    (bt, len)
}

/// libyara `_yr_modified_base64_encode` + `_yr_base64_get_base64_substring`.
fn b64_nodes(s: &[u8], alphabet: &[u8], wide: bool, out: &mut Vec<Vec<u8>>) {
    for i in 0..=2usize {
        if i == 1 && s.len() == 1 {
            continue;
        }
        let mut tmp = vec![b'A'; i];
        tmp.extend_from_slice(s);
        let len = tmp.len();
        let pad = if len % 3 != 0 { 3 - len % 3 } else { 0 };
        let mut enc = Vec::with_capacity(len * 4 / 3 + 4);
        let mut c = tmp.chunks_exact(3);
        for t in &mut c {
            enc.push(alphabet[(t[0] >> 2) as usize]);
            enc.push(alphabet[((t[0] & 3) << 4 | t[1] >> 4) as usize]);
            enc.push(alphabet[((t[1] & 15) << 2 | t[2] >> 6) as usize]);
            enc.push(alphabet[(t[2] & 63) as usize]);
        }
        let r = c.remainder();
        if !r.is_empty() {
            enc.push(alphabet[(r[0] >> 2) as usize]);
            if r.len() == 1 {
                enc.push(alphabet[((r[0] & 3) << 4) as usize]);
                enc.push(b'=');
            } else {
                enc.push(alphabet[((r[0] & 3) << 4 | r[1] >> 4) as usize]);
                enc.push(alphabet[((r[1] & 15) << 2) as usize]);
            }
            enc.push(b'=');
        }
        let trailing = if pad > 0 { pad + 1 } else { 0 };
        let leading = if i > 0 { i + 1 } else { 0 };
        if enc.len() <= leading + trailing {
            continue;
        }
        let sub = &enc[leading..enc.len() - trailing];
        out.push(if wide { widen(sub) } else { sub.to_vec() });
    }
}

fn plain_check(pat: Vec<u8>, wide: bool, nocase: bool, xor: bool, searched: bool, yatom: bool, atom: (usize, usize)) -> Check {
    let mut pat = pat;
    let mut fold = vec![0u8; pat.len()];
    if nocase {
        for (p, f) in pat.iter_mut().zip(fold.iter_mut()) {
            if p.is_ascii_alphabetic() {
                *p |= 0x20;
                *f = 0x20;
            }
        }
    }
    let (bt, len) = atom;
    let (ybt, ylen) = if wide { (bt * 2, (len * 2).min(4)) } else { (bt, len) };
    Check { pat, fold, wide, xor, searched, yatom, ybt: ybt as u32, ylen: ylen as u32 }
}

impl TextStr {
    /// Compile a text string with its modifiers (errors mirror yara compile errors).
    pub fn new(s: &[u8], mods: &Modifiers) -> Result<TextStr, String> {
        if s.is_empty() {
            return Err("empty string".into());
        }
        let b64 = mods.base64.is_some() || mods.base64wide.is_some();
        if mods.xor.is_some() && mods.nocase {
            return Err("invalid modifier combination: xor nocase".into());
        }
        if b64 && mods.nocase {
            return Err("invalid modifier combination: base64 nocase".into());
        }
        if b64 && mods.fullword {
            return Err("invalid modifier combination: base64 fullword".into());
        }
        if b64 && mods.xor.is_some() {
            return Err("invalid modifier combination: base64 xor".into());
        }
        if let Some((a, b)) = mods.xor {
            if a > b {
                return Err("lower bound for xor range exceeded upper bound".into());
            }
        }
        let ascii = mods.ascii || (!mods.wide && !b64);
        let wide = mods.wide;
        if b64 {
            return Self::new_base64(s, mods, ascii, wide);
        }
        let n = s.len();
        let fits = (if wide { 2 * n } else { n }) <= 4;
        let atom = yara_atom(s);
        let mut checks = Vec::new();
        let xor = mods.xor.is_some();
        if fits && xor {
            // Atoms are the xored variants themselves (keys in range); shortest first.
            if ascii {
                checks.push(plain_check(s.to_vec(), false, false, true, true, true, atom));
            }
            if wide {
                checks.push(plain_check(widen(s), true, false, true, true, true, atom));
            }
        } else if xor {
            // _yr_scan_verify_literal_match order. Plain forms are the key-0 case of
            // the xor forms (searched through those); the ascii xor form is tried
            // even for wide-only strings.
            if ascii {
                checks.push(plain_check(s.to_vec(), false, false, false, false, false, atom));
            }
            if wide {
                checks.push(plain_check(widen(s), true, false, false, false, false, atom));
                checks.push(plain_check(widen(s), true, false, true, true, true, atom));
            }
            checks.push(plain_check(s.to_vec(), false, false, true, true, ascii, atom));
        } else {
            if ascii {
                checks.push(plain_check(s.to_vec(), false, mods.nocase, false, true, true, atom));
            }
            if wide {
                checks.push(plain_check(widen(s), true, mods.nocase, false, true, true, atom));
            }
        }
        let max_len = checks.iter().map(|c| c.len()).max().unwrap_or(0);
        Ok(TextStr { checks, fits, fullword: mods.fullword, xor: mods.xor, first: s[0], base64: false, max_len })
    }

    fn new_base64(s: &[u8], mods: &Modifiers, ascii: bool, wide: bool) -> Result<TextStr, String> {
        let a1 = mods.base64.as_ref().map(|a| a.as_deref().unwrap_or(DEFAULT_ALPHABET));
        let a2 = mods.base64wide.as_ref().map(|a| a.as_deref().unwrap_or(DEFAULT_ALPHABET));
        let alphabet: &[u8] = match (a1, a2) {
            (Some(x), Some(y)) if x != y => return Err("can not specify multiple alphabets".into()),
            (Some(x), _) => x,
            (_, Some(y)) => y,
            _ => DEFAULT_ALPHABET,
        };
        if alphabet.len() != 64 {
            return Err("length of base64 alphabet must be 64".into());
        }
        let (b, bw) = (mods.base64.is_some(), mods.base64wide.is_some());
        let mut alts = Vec::new();
        if wide {
            let ws = widen(s);
            if b {
                b64_nodes(&ws, alphabet, false, &mut alts);
            }
            if bw {
                b64_nodes(&ws, alphabet, true, &mut alts);
            }
        }
        if ascii || !wide {
            if b {
                b64_nodes(s, alphabet, false, &mut alts);
            }
            if bw {
                b64_nodes(s, alphabet, true, &mut alts);
            }
        }
        if alts.is_empty() {
            return Err("empty base64 string".into());
        }
        let checks: Vec<Check> = alts
            .into_iter()
            .map(|a| {
                let at = yara_atom(&a);
                plain_check(a, false, false, false, true, true, at)
            })
            .collect();
        let max_len = checks.iter().map(|c| c.len()).max().unwrap_or(0);
        Ok(TextStr { checks, fits: false, fullword: false, xor: None, first: s[0], base64: true, max_len })
    }

    /// The libyara match at string start `s`, if any. `known` is the index of a check
    /// already verified to match at `s` (`usize::MAX` if none).
    #[inline]
    pub fn resolve(&self, data: &[u8], s: usize, known: usize) -> Option<Match> {
        if s >= data.len() {
            return None;
        }
        if self.base64 {
            // The alternative whose atom the scan reaches first.
            let mut best: Option<(u32, u32, usize)> = None;
            for (i, c) in self.checks.iter().enumerate() {
                if i == known || c.matches(data, s, 0) {
                    let k = (c.ybt + c.ylen, u32::MAX - c.ylen, i);
                    if best.is_none_or(|b| (k.0, k.1) < (b.0, b.1)) {
                        best = Some(k);
                    }
                }
            }
            return best.map(|(_, _, i)| Match { offset: s, len: self.checks[i].len(), xor_key: 0 });
        }
        let key = match self.xor {
            Some((lo, hi)) => {
                let k = data[s] ^ self.first;
                if self.fits {
                    if k < lo || k > hi {
                        return None;
                    }
                } else if !self.checks.iter().any(|c| c.yatom && c.atom_hits(data, s, self.xor)) {
                    return None;
                }
                k
            }
            None => 0,
        };
        for (i, c) in self.checks.iter().enumerate() {
            if i != known && !c.matches(data, s, if c.xor { key } else { 0 }) {
                continue;
            }
            let len = c.len();
            if self.fullword && !fullword_ok(data, s, len, c.wide) {
                if self.fits {
                    continue;
                }
                return None;
            }
            return Some(Match { offset: s, len, xor_key: key });
        }
        None
    }

    /// Position (libyara's scan index) at which libyara would record the match at `s`
    /// — used to keep the first [`MAX_STRING_MATCHES`] in libyara's order.
    pub fn discovery(&self, data: &[u8], m: &Match) -> usize {
        let s = m.offset;
        if self.fits {
            return s + m.len;
        }
        let mut t = usize::MAX;
        for c in &self.checks {
            if c.yatom && c.atom_hits(data, s, self.xor) {
                t = t.min(s + (c.ybt + c.ylen) as usize);
            }
        }
        if t == usize::MAX { s + m.len } else { t }
    }
}

/// Keeps the first `MAX_STRING_MATCHES` matches of `v` in libyara's discovery order
/// (`key(m)`), returning them sorted by offset.
pub fn cap_by_discovery(v: &mut Vec<Match>, key: impl Fn(&Match) -> usize) {
    if v.len() <= MAX_STRING_MATCHES {
        return;
    }
    let mut t: Vec<(usize, usize, u32)> = v.iter().enumerate().map(|(i, m)| (key(m), m.offset, i as u32)).collect();
    t.sort_unstable();
    t.truncate(MAX_STRING_MATCHES);
    let mut keep: Vec<Match> = t.iter().map(|&(_, _, i)| v[i as usize]).collect();
    keep.sort_unstable_by_key(|m| m.offset);
    *v = keep;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_literal_base64_nodes() {
        let mut v = Vec::new();
        b64_nodes(b"This program cannot", DEFAULT_ALPHABET, false, &mut v);
        let v: Vec<String> = v.into_iter().map(|x| String::from_utf8(x).unwrap()).collect();
        // Known values from the yara documentation example.
        assert_eq!(v[0], "VGhpcyBwcm9ncmFtIGNhbm5vd");
        assert_eq!(v[1], "RoaXMgcHJvZ3JhbSBjYW5ub3");
        assert_eq!(v[2], "UaGlzIHByb2dyYW0gY2Fubm90");
    }

    #[test]
    fn yara_literal_atom_quality() {
        // Examples from atoms.c.
        assert_eq!(atom_quality(&[1, 2, 3, 4]) - 167, 88);
        assert_eq!(atom_quality(&[1, 2]) - 167, 44);
        assert_eq!(atom_quality(&[0x61, 0x62]) - 167, 40);
        assert_eq!(atom_quality(&[0x61, 0x61]) - 167, 38);
        assert_eq!(atom_quality(&[0, 1]) - 167, 36);
        // (the atoms.c comment says 21, the code gives 20 + 2 * unique)
        assert_eq!(atom_quality(&[1]) - 167, 22);
        assert_eq!(yara_atom(b"abcdef\x01\x02\x03\x04"), (6, 4));
        assert_eq!(yara_atom(b"ab"), (0, 2));
    }

    #[test]
    fn yara_literal_eq_fold() {
        let c = plain_check(b"HeLLo wOrld!".to_vec(), false, true, false, true, true, (0, 4));
        assert!(c.matches(b"xxhello WORLD!", 2, 0));
        assert!(!c.matches(b"xxhello WORLD?", 2, 0));
        assert!(!c.matches(b"xxhello WORLD", 2, 0));
        let c = plain_check(b"@[".to_vec(), false, true, false, true, true, (0, 2));
        assert!(c.matches(b"@[", 0, 0));
        assert!(!c.matches(b"`{", 0, 0));
    }
}
