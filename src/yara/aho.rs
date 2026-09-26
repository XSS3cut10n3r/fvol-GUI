//! Aho-Corasick multi-pattern search (overlapping, all matches), used for YARA atoms
//! and multi-literal prefilters. Owner: strings/Aho-Corasick owner.
//!
//! Layout: a fully determinized automaton (every failure transition resolved at build
//! time) over byte equivalence classes, stored as one flat `u32` table whose entries are
//! *premultiplied* state indices (`state_id * stride`), so the hot loop is a single
//! dependent load per byte: `s = trans[s + class[b]]`. States are renumbered so that all
//! states carrying matches come last: "is this a match state" is one compare. The root
//! state is 0; while in the root the scanner skips ahead with a SIMD byte-set search
//! over the bytes that leave the root (when that set is rare enough to pay off).

use super::memchr::ByteSetFinder;
use super::regex::literal::BYTE_FREQ;

/// Compiled Aho-Corasick automaton.
#[derive(Clone, Debug)]
pub struct AhoCorasick {
    classes: [u8; 256],
    stride: u32,
    trans: Vec<u32>,
    /// Premultiplied id of the first match state.
    match_min: u32,
    /// For match state `(s - match_min) / stride`: range into `out_list`.
    out_ranges: Vec<(u32, u32)>,
    out_list: Vec<u32>,
    pat_lens: Vec<u32>,
    prefilter: Option<ByteSetFinder>,
}

impl AhoCorasick {
    /// Builds the automaton. Pattern `i` is reported with id `i`; empty patterns never
    /// match.
    pub fn new<P: AsRef<[u8]>>(patterns: &[P]) -> AhoCorasick {
        // --- trie (sparse children during construction) ---
        let mut children: Vec<Vec<(u8, u32)>> = vec![Vec::new()];
        let mut outs: Vec<Vec<u32>> = vec![Vec::new()];
        let mut used = [false; 256];
        let mut pat_lens = Vec::with_capacity(patterns.len());
        for (pid, p) in patterns.iter().enumerate() {
            let p = p.as_ref();
            pat_lens.push(p.len() as u32);
            if p.is_empty() {
                continue;
            }
            let mut s = 0usize;
            for &b in p {
                used[b as usize] = true;
                let next = children[s].iter().find(|&&(c, _)| c == b).map(|&(_, t)| t as usize);
                s = match next {
                    Some(t) => t,
                    None => {
                        let t = children.len();
                        children.push(Vec::new());
                        outs.push(Vec::new());
                        children[s].push((b, t as u32));
                        t
                    }
                };
            }
            outs[s].push(pid as u32);
        }
        let nstates = children.len();

        // --- byte classes: every byte used by a pattern gets its own class ---
        let mut classes = [0u8; 256];
        let mut nclasses = 1usize;
        for b in 0..256 {
            if used[b] && nclasses < 256 {
                classes[b] = nclasses as u8;
                nclasses += 1;
            }
        }
        // If all 256 bytes are used, class 0 is shared by one real byte: recompute as
        // identity (256 classes; `nclasses` still fits u32 stride).
        if used.iter().all(|&u| u) {
            for (b, c) in classes.iter_mut().enumerate() {
                *c = b as u8;
            }
            nclasses = 256;
        }
        let stride = nclasses;

        // --- BFS: failure links + full DFA over classes (state ids = trie ids) ---
        let mut dfa = vec![0u32; nstates * stride];
        let mut fail = vec![0u32; nstates];
        let mut order = Vec::with_capacity(nstates);
        let mut queue = std::collections::VecDeque::new();
        // Root transitions.
        for &(b, t) in &children[0] {
            dfa[classes[b as usize] as usize] = t;
            fail[t as usize] = 0;
            queue.push_back(t);
        }
        order.push(0u32);
        while let Some(s) = queue.pop_front() {
            order.push(s);
            let s = s as usize;
            // Inherit outputs of the failure state (already complete: BFS order).
            let f = fail[s] as usize;
            if !outs[f].is_empty() {
                let inherited = outs[f].clone();
                outs[s].extend(inherited);
            }
            // Default: failure state's row.
            for c in 0..stride {
                dfa[s * stride + c] = dfa[f * stride + c];
            }
            for &(b, t) in &children[s] {
                let c = classes[b as usize] as usize;
                // fail(t) = delta(fail(s), b), which is the (already complete) row of f.
                fail[t as usize] = if s == 0 { 0 } else { dfa[f * stride + c] };
                dfa[s * stride + c] = t;
                queue.push_back(t);
            }
        }

        // --- renumber: root first, non-match states, then match states ---
        let mut new_id = vec![0u32; nstates];
        let mut next = 0u32;
        for &s in &order {
            if outs[s as usize].is_empty() {
                new_id[s as usize] = next;
                next += 1;
            }
        }
        let first_match = next;
        for &s in &order {
            if !outs[s as usize].is_empty() {
                new_id[s as usize] = next;
                next += 1;
            }
        }
        let mut trans = vec![0u32; nstates * stride];
        let mut out_ranges = vec![(0u32, 0u32); nstates - first_match as usize];
        let mut out_list = Vec::new();
        for s in 0..nstates {
            let ns = new_id[s] as usize;
            for c in 0..stride {
                trans[ns * stride + c] = new_id[dfa[s * stride + c] as usize] * stride as u32;
            }
            if ns >= first_match as usize {
                let start = out_list.len() as u32;
                // Report longer (own) matches first, then suffix matches, like libyara.
                let mut o = outs[s].clone();
                o.sort_by(|&a, &b| pat_lens[b as usize].cmp(&pat_lens[a as usize]).then(a.cmp(&b)));
                o.dedup();
                out_list.extend_from_slice(&o);
                out_ranges[ns - first_match as usize] = (start, out_list.len() as u32);
            }
        }

        // --- root skip prefilter ---
        let mut start = [false; 256];
        let mut freq = 0u64;
        let mut count = 0usize;
        for b in 0..256 {
            if trans[classes[b] as usize] != 0 {
                start[b] = true;
                freq += BYTE_FREQ[b] as u64;
                count += 1;
            }
        }
        // Worth it when the bytes leaving the root are rare (< ~12% of memory bytes).
        let prefilter = if count > 0 && count < 256 && freq < (1 << 20) / 8 {
            Some(ByteSetFinder::new(&start))
        } else {
            None
        };

        AhoCorasick {
            classes,
            stride: stride as u32,
            trans,
            match_min: first_match * stride as u32,
            out_ranges,
            out_list,
            pat_lens,
            prefilter,
        }
    }

    /// Number of patterns the automaton was built from.
    pub fn pattern_count(&self) -> usize {
        self.pat_lens.len()
    }

    /// Length of pattern `id`.
    pub fn pattern_len(&self, id: u32) -> usize {
        self.pat_lens.get(id as usize).copied().unwrap_or(0) as usize
    }

    /// Number of automaton states.
    pub fn state_count(&self) -> usize {
        self.trans.len() / self.stride as usize
    }

    /// Streams `hay[from..to]` through the automaton starting in `*state` (0 = root;
    /// keep the value between calls to scan contiguous ranges) and calls
    /// `f(pattern, end)` for every occurrence ending at `end` (exclusive), overlapping
    /// ones included, in order of `end`.
    #[inline]
    pub fn scan<F: FnMut(u32, usize)>(&self, hay: &[u8], from: usize, to: usize, state: &mut u32, mut f: F) {
        let to = to.min(hay.len());
        let hay = &hay[..to];
        let trans = &self.trans[..];
        let classes = &self.classes;
        let match_min = self.match_min;
        let mut s = *state;
        let mut i = from;
        if s as usize >= trans.len() || s % self.stride != 0 {
            s = 0;
        }
        match &self.prefilter {
            Some(pf) => {
                while i < to {
                    if s == 0 {
                        match pf.find(hay, i) {
                            Some(j) => i = j,
                            None => break,
                        }
                    }
                    // Run the DFA until a match, the root or the end.
                    loop {
                        let b = hay[i];
                        s = trans[(s + classes[b as usize] as u32) as usize];
                        i += 1;
                        if s >= match_min || s == 0 || i >= to {
                            break;
                        }
                    }
                    if s >= match_min {
                        self.report(s, i, &mut f);
                    }
                }
            }
            None => {
                while i < to {
                    let b = hay[i];
                    s = trans[(s + classes[b as usize] as u32) as usize];
                    i += 1;
                    if s >= match_min {
                        self.report(s, i, &mut f);
                    }
                }
            }
        }
        *state = s;
    }

    #[inline]
    fn report<F: FnMut(u32, usize)>(&self, s: u32, end: usize, f: &mut F) {
        let k = ((s - self.match_min) / self.stride) as usize;
        if let Some(&(a, b)) = self.out_ranges.get(k) {
            for &p in &self.out_list[a as usize..b as usize] {
                f(p, end);
            }
        }
    }

    /// All (pattern, start) occurrences in `hay`, overlapping, ordered by end.
    pub fn find_all(&self, hay: &[u8]) -> Vec<(u32, usize)> {
        let mut v = Vec::new();
        let mut st = 0;
        self.scan(hay, 0, hay.len(), &mut st, |p, end| v.push((p, end - self.pat_lens[p as usize] as usize)));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(pats: &[&[u8]], hay: &[u8]) -> Vec<(u32, usize)> {
        let mut v = Vec::new();
        for end in 1..=hay.len() {
            // Same order as the automaton: longer patterns first at the same end.
            let mut here: Vec<(u32, usize)> = Vec::new();
            for (i, p) in pats.iter().enumerate() {
                if !p.is_empty() && p.len() <= end && &hay[end - p.len()..end] == *p {
                    here.push((i as u32, end - p.len()));
                }
            }
            here.sort_by(|a, b| pats[b.0 as usize].len().cmp(&pats[a.0 as usize].len()).then(a.0.cmp(&b.0)));
            v.extend(here);
        }
        v
    }

    #[test]
    fn yara_aho_basic() {
        let pats: Vec<&[u8]> = vec![b"he", b"she", b"his", b"hers", b"e", b"", b"sh"];
        let hay = b"ushers and his shells hehe";
        let ac = AhoCorasick::new(&pats);
        assert_eq!(ac.find_all(hay), naive(&pats, hay));
    }

    #[test]
    fn yara_aho_random() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut rnd = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..200 {
            let alpha = 2 + (round % 5) as u64;
            let np = 1 + (rnd() % 12) as usize;
            let pats: Vec<Vec<u8>> = (0..np)
                .map(|_| (0..1 + rnd() % 5).map(|_| b'a' + (rnd() % alpha) as u8).collect())
                .collect();
            let hay: Vec<u8> = (0..300).map(|_| b'a' + (rnd() % (alpha + 1)) as u8).collect();
            let refs: Vec<&[u8]> = pats.iter().map(|p| &p[..]).collect();
            let ac = AhoCorasick::new(&refs);
            assert_eq!(ac.find_all(&hay), naive(&refs, &hay), "round {round}");
            // Chunked streaming gives the same result.
            let mut st = 0;
            let mut v = Vec::new();
            let mut p = 0;
            while p < hay.len() {
                let e = (p + 1 + (rnd() % 40) as usize).min(hay.len());
                ac.scan(&hay, p, e, &mut st, |id, end| v.push((id, end - refs[id as usize].len())));
                p = e;
            }
            assert_eq!(v, naive(&refs, &hay), "chunked round {round}");
        }
    }

    #[test]
    fn yara_aho_all_bytes_and_prefilter() {
        let pats: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b, b.wrapping_add(1)]).collect();
        let refs: Vec<&[u8]> = pats.iter().map(|p| &p[..]).collect();
        let hay: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
        let ac = AhoCorasick::new(&refs);
        assert_eq!(ac.find_all(&hay), naive(&refs, &hay));
        let pats2: Vec<&[u8]> = vec![b"\xf1\xf2zz", b"\xf3q"];
        let mut hay2 = vec![0u8; 5000];
        hay2[4000..4004].copy_from_slice(b"\xf1\xf2zz");
        hay2[10..12].copy_from_slice(b"\xf3q");
        let ac2 = AhoCorasick::new(&pats2);
        assert!(ac2.prefilter.is_some());
        assert_eq!(ac2.find_all(&hay2), vec![(1, 10), (0, 4000)]);
    }
}
