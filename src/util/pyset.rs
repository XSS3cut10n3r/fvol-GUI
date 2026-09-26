//! CPython `set` iteration order, plus CPython's hash functions for the key types plugins put in
//! sets (ints, str, tuples).
//!
//! Python iterates a set in hash-table slot order. For ints (hash = value mod 2^61-1, never
//! randomized) that order is deterministic but depends on CPython's open-addressing scheme
//! (linear probes + perturbation, resize policy); plugins that iterate a python `set` of ints
//! (e.g. pstree's children sets) use [`PyIntSet`] to reproduce python's output order byte for
//! byte. `str` hashes are randomized per process unless `PYTHONHASHSEED=0`;
//! [`py_hash_str_seed0`] gives the `PYTHONHASHSEED=0` value (SipHash-1-3 with a zero key), so
//! sets of strings / tuples can at least match a python run with hash randomization disabled.
//!
//! Mirrors `Objects/setobject.c` (CPython 3.14): `PySet_MINSIZE` 8, `LINEAR_PROBES` 9,
//! `PERTURB_SHIFT` 5, grow when `fill*5 >= mask*3` to the smallest power of two > `used*4`
//! (`used*2` above 50000 elements); removal leaves dummies; `copy` / `update` / `difference` /
//! `union` follow `set_merge` / `set_difference` (table sizes and slot order included).

const MINSIZE: usize = 8;
const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;
const MODULUS: u64 = (1 << 61) - 1;

/// python `hash(int)` as the unsigned `size_t` CPython indexes with.
#[inline]
pub fn py_hash_int(v: i128) -> u64 {
    let m = MODULUS as i128;
    let h: i64 = if v >= 0 { (v % m) as i64 } else { -(((-v) % m) as i64) };
    (if h == -1 { -2 } else { h }) as u64
}

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// CPython's `siphash13(k0, k1, src)` (Python/pyhash.c).
pub fn siphash13(k0: u64, k1: u64, src: &[u8]) -> u64 {
    let mut b: u64 = (src.len() as u64) << 56;
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;
    let mut chunks = src.chunks_exact(8);
    for c in &mut chunks {
        let mi = u64::from_le_bytes(c.try_into().unwrap());
        v3 ^= mi;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= mi;
    }
    let mut t = [0u8; 8];
    let rest = chunks.remainder();
    t[..rest.len()].copy_from_slice(rest);
    b |= u64::from_le_bytes(t);
    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;
    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    (v0 ^ v1) ^ (v2 ^ v3)
}

/// python `hash(s)` for a `str` when `PYTHONHASHSEED=0` (hash randomization disabled): SipHash-1-3
/// with a zero key over the string's internal representation (latin-1 / UCS-2 / UCS-4).
pub fn py_hash_str_seed0(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    let max = s.chars().map(|c| c as u32).max().unwrap_or(0);
    let bytes: Vec<u8> = if max < 0x100 {
        s.chars().map(|c| c as u32 as u8).collect()
    } else if max < 0x10000 {
        s.chars().flat_map(|c| (c as u32 as u16).to_le_bytes()).collect()
    } else {
        s.chars().flat_map(|c| (c as u32).to_le_bytes()).collect()
    };
    let h = siphash13(0, 0, &bytes);
    if h == u64::MAX { (-2i64) as u64 } else { h }
}

/// python `hash(tuple)` from the element hashes (CPython's xxHash-based `tuplehash`).
pub fn py_hash_tuple(items: &[u64]) -> u64 {
    const P1: u64 = 11400714785074694791;
    const P2: u64 = 14029467366897019727;
    const P5: u64 = 2870177450012600261;
    let mut acc = P5;
    for &lane in items {
        acc = acc.wrapping_add(lane.wrapping_mul(P2));
        acc = acc.rotate_left(31);
        acc = acc.wrapping_mul(P1);
    }
    acc = acc.wrapping_add((items.len() as u64) ^ (P5 ^ 3527539));
    if acc == u64::MAX { 1546275796 } else { acc }
}

/// One slot of a CPython set table.
#[derive(Clone, Debug)]
enum Slot<T> {
    Empty,
    /// a removed entry (`dummy`, hash -1)
    Dummy,
    Full(u64, T),
}

/// A python `set` of values with caller-supplied python hashes: CPython's table (slots,
/// dummies left by removals, `fill` / `used`), so iteration order is python's.
#[derive(Clone, Debug)]
pub struct PySet<T> {
    table: Vec<Slot<T>>,
    /// active entries
    used: usize,
    /// active + dummy entries
    fill: usize,
}

impl<T: PartialEq> Default for PySet<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// `set_insert_clean`: `h` into the first free slot of its probe sequence (the table has no
/// dummies and does not contain the value).
fn insert_clean<T>(table: &mut [Slot<T>], h: u64, v: T) {
    let mask = table.len() - 1;
    let mut i = (h as usize) & mask;
    let mut perturb = h;
    let slot = 'outer: loop {
        if matches!(table[i], Slot::Empty) {
            break i;
        }
        if i + LINEAR_PROBES <= mask {
            for j in 1..=LINEAR_PROBES {
                if matches!(table[i + j], Slot::Empty) {
                    break 'outer i + j;
                }
            }
        }
        perturb >>= PERTURB_SHIFT;
        i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
    };
    table[slot] = Slot::Full(h, v);
}

impl<T: PartialEq> PySet<T> {
    pub fn new() -> PySet<T> {
        PySet { table: (0..MINSIZE).map(|_| Slot::Empty).collect(), used: 0, fill: 0 }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// `set_lookkey`: the slot holding `v`, or `None`.
    fn find(&self, h: u64, v: &T) -> Option<usize> {
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match &self.table[i + j] {
                    Slot::Empty => return None,
                    Slot::Full(eh, ev) if *eh == h && ev == v => return Some(i + j),
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    pub fn contains(&self, h: u64, v: &T) -> bool {
        self.find(h, v).is_some()
    }

    /// python `s.add(v)` where `h == hash(v)` (`set_add_entry`: the first dummy of the probe
    /// sequence is reused).
    pub fn add(&mut self, h: u64, v: T) {
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        let mut freeslot: Option<usize> = None;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match &self.table[i + j] {
                    Slot::Empty => {
                        match freeslot {
                            Some(f) => {
                                self.table[f] = Slot::Full(h, v);
                                self.used += 1;
                            }
                            None => {
                                self.table[i + j] = Slot::Full(h, v);
                                self.used += 1;
                                self.fill += 1;
                                if self.fill * 5 >= mask * 3 {
                                    let minused = if self.used > 50000 { self.used * 2 } else { self.used * 4 };
                                    self.resize(minused);
                                }
                            }
                        }
                        return;
                    }
                    Slot::Full(eh, ev) if *eh == h && *ev == v => return,
                    Slot::Dummy if freeslot.is_none() => freeslot = Some(i + j),
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    /// python `s.discard(v)` (`set_discard_entry`: the slot becomes a dummy; sets never
    /// shrink).
    pub fn discard(&mut self, h: u64, v: &T) -> bool {
        match self.find(h, v) {
            Some(i) => {
                self.table[i] = Slot::Dummy;
                self.used -= 1;
                true
            }
            None => false,
        }
    }

    /// `set_table_resize`: a table of the smallest power of two > `minused`, the active entries
    /// re-inserted in slot order.
    fn resize(&mut self, minused: usize) {
        let mut newsize = MINSIZE;
        while newsize <= minused {
            newsize <<= 1;
        }
        let old = std::mem::replace(&mut self.table, (0..newsize).map(|_| Slot::Empty).collect());
        for s in old {
            if let Slot::Full(h, v) = s {
                insert_clean(&mut self.table, h, v);
            }
        }
        self.fill = self.used;
    }

    /// Elements in python iteration order.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.table.iter().filter_map(|e| match e {
            Slot::Full(_, v) => Some(v),
            _ => None,
        })
    }

    /// (hash, element) in python iteration order.
    fn entries(&self) -> impl Iterator<Item = (u64, &T)> + '_ {
        self.table.iter().filter_map(|e| match e {
            Slot::Full(h, v) => Some((*h, v)),
            _ => None,
        })
    }
}

impl<T: PartialEq + Clone> PySet<T> {
    /// `set_merge` (`s.update(other)` for a set `other`).
    pub fn update(&mut self, other: &PySet<T>) {
        if other.used == 0 {
            return;
        }
        // one big resize first
        if (self.fill + other.used) * 5 >= (self.table.len() - 1) * 3 {
            self.resize((self.used + other.used) * 2);
        }
        if self.fill == 0 && self.table.len() == other.table.len() && other.fill == other.used {
            // empty table of the same size, no dummies to drop: the slots are copied
            self.table.clone_from(&other.table);
            self.fill = other.fill;
            self.used = other.used;
            return;
        }
        if self.fill == 0 {
            self.fill = other.used;
            self.used = other.used;
            for (h, v) in other.entries() {
                insert_clean(&mut self.table, h, v.clone());
            }
            return;
        }
        for (h, v) in other.entries() {
            self.add(h, v.clone());
        }
    }

    /// `set.copy()` (`make_new_set` from a set).
    pub fn copy(&self) -> PySet<T> {
        let mut s = PySet::new();
        s.update(self);
        s
    }

    /// python `self.difference(other)` (`set_difference`: a copy with `other`'s elements
    /// discarded when `self` is more than four times larger, else the elements not in `other`
    /// added to a new set in iteration order).
    pub fn difference(&self, other: &PySet<T>) -> PySet<T> {
        if (self.used >> 2) > other.used {
            let mut r = self.copy();
            for (h, v) in other.entries() {
                r.discard(h, v);
            }
            return r;
        }
        let mut r = PySet::new();
        for (h, v) in self.entries() {
            if !other.contains(h, v) {
                r.add(h, v.clone());
            }
        }
        r
    }

    /// python `self.union(other)` (`set_union`: a copy updated with `other`).
    pub fn union(&self, other: &PySet<T>) -> PySet<T> {
        let mut r = self.copy();
        r.update(other);
        r
    }
}

/// An insertion-only python `set` of non-negative ints.
#[derive(Clone, Debug, Default)]
pub struct PyIntSet(PySet<u64>);

impl PyIntSet {
    pub fn new() -> PyIntSet {
        PyIntSet(PySet::new())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains(&self, v: u64) -> bool {
        self.0.contains(py_hash_int(v as i128), &v)
    }
    /// python `s.add(v)`.
    pub fn add(&mut self, v: u64) {
        self.0.add(py_hash_int(v as i128), v)
    }
    /// Elements in python iteration order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn order_matches_cpython() {
        // python 3.14: s=set(); [s.add(x) for x in [...]]; list(s)
        let mut s = PyIntSet::new();
        for x in [4, 344, 1864, 100, 468, 20, 36, 12, 1000, 8] {
            s.add(x);
        }
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![100, 4, 36, 1864, 1000, 8, 12, 468, 20, 344]);
        assert!(s.contains(1864) && !s.contains(5));
    }

    #[test]
    fn hashes_match_cpython_seed0() {
        // PYTHONHASHSEED=0 python3.14 -c 'print(hash("kernel"), hash("Process 4"), hash(("kernel", 4096)))'
        assert_eq!(py_hash_str_seed0("kernel") as i64, 3506346307321274238);
        assert_eq!(py_hash_str_seed0("Process 4") as i64, 7813105681752815202);
        let t = py_hash_tuple(&[py_hash_str_seed0("kernel"), py_hash_int(4096)]);
        assert_eq!(t as i64, 278577473750989746);
        assert_eq!(py_hash_str_seed0("\u{e9}") as i64, 6047309291227476195);
        assert_eq!(py_hash_str_seed0("\u{100}") as i64, 75343234424780393);
        assert_eq!(py_hash_str_seed0("\u{1f600}x") as i64, -8926728262118538918);
        assert_eq!(py_hash_int(-1) as i64, -2);
        assert_eq!(py_hash_int((1 << 61) - 1), 0);
    }

    /// hash(tuple(s)) of the set's iteration order, checked against python.
    fn order_hash<T: PartialEq>(s: &PySet<T>, h: impl Fn(&T) -> u64) -> i64 {
        let hs: Vec<u64> = s.iter().map(h).collect();
        py_hash_tuple(&hs) as i64
    }

    #[test]
    fn set_orders_match_cpython() {
        // python: x=12345; x=(x*6364136223846793005+1442695040888963407)%2**64; s.add(x>>24)
        let lcg = |n: usize| {
            let mut x: u64 = 12345;
            (0..n)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    x >> 24
                })
                .collect::<Vec<u64>>()
        };
        for (n, want) in [
            (5, 3367948233325309201i64),
            (30, -4496338299145824952),
            (200, -6266506675193359391),
            (3000, -2340033921106909456),
            (60000, 7098021770626018906),
        ] {
            let mut s = PySet::new();
            for x in lcg(n) {
                s.add(py_hash_int(x as i128), x);
            }
            assert_eq!(order_hash(&s, |x| py_hash_int(*x as i128)), want, "n={n}");
        }
        let th = |t: &(String, u64)| py_hash_tuple(&[py_hash_str_seed0(&t.0), py_hash_int(t.1 as i128)]);
        let mut s = PySet::new();
        for i in 0..40u64 {
            let a = ("kernel".to_string(), i * 4096 + 0xf800_0000_0000);
            let b = (format!("Process {}", i * 4), i * 8192);
            s.add(th(&a), a);
            s.add(th(&b), b);
        }
        assert_eq!(order_hash(&s, th), 2667392356262095263);
    }

    /// `set(L).difference(C).union(U)` (the shape of volatility3's `SqliteCache.update()`), as
    /// computed by CPython 3.14 with PYTHONHASHSEED=0 (the generator is mirrored from the python
    /// script that produced the expected `hash(tuple(result))`).
    #[test]
    fn difference_union_orders_match_cpython() {
        let urls = |n: u64, salt: u64| -> Vec<String> {
            (0..n)
                .map(|i| format!("file:///home/u/sym{salt}/windows/k{}.pdb/{:08X}-{salt}.json.xz", (i * 7919 + salt) % 100003, i * 2654435761 % (1 << 32)))
                .collect()
        };
        let h = |s: &String| py_hash_str_seed0(s);
        for (n, salt, cstep, gone, ustep, want) in [
            (3u64, 1u64, 0usize, 0u64, 0usize, 3263309288474546317i64),
            (7, 2, 0, 0, 0, -56865205525427900),
            (40, 3, 0, 0, 0, -5652103069197437542),
            (400, 4, 0, 0, 0, -5122057115771434288),
            (400, 5, 1, 3, 7, -2192519192994327067),
            (400, 6, 2, 0, 5, 4977396002853528967),
            (400, 7, 9, 2, 3, -6104756580497946410),
            (1500, 8, 1, 10, 50, -1771148622409251340),
            (1500, 9, 13, 0, 2, 9026973223313870464),
            (60, 10, 1, 200, 4, 910200117382248944),
            (100, 11, 3, 500, 2, 5086794661487369987),
            (12, 12, 2, 0, 0, 3033697607877991129),
            (9, 13, 3, 0, 1, -128141301043832703),
            (5000, 14, 5, 7, 11, -5082319151765759809),
        ] {
            let l = urls(n, salt);
            let mut all = PySet::new();
            for s in &l {
                all.add(h(s), s.clone());
            }
            let mut c = PySet::new();
            if cstep > 0 {
                for s in l.iter().step_by(cstep) {
                    c.add(h(s), s.clone());
                }
            }
            for g in 0..gone {
                let s = format!("file:///gone/{salt}/{g}.json");
                c.add(h(&s), s);
            }
            let mut u = PySet::new();
            if ustep > 0 && cstep > 0 {
                for s in l.iter().step_by(cstep * ustep) {
                    u.add(h(s), s.clone());
                }
            }
            let f = all.difference(&c).union(&u);
            assert_eq!(order_hash(&f, h), want, "n={n} salt={salt}");
        }
    }
}
