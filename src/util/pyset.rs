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
//! (`used*2` above 50000 elements). Only insertion is supported (no removal).

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

/// An insertion-only python `set` of values with caller-supplied python hashes.
#[derive(Clone, Debug)]
pub struct PySet<T> {
    /// slots: Some((hash, value))
    table: Vec<Option<(u64, T)>>,
    used: usize,
}

impl<T: PartialEq> Default for PySet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PartialEq> PySet<T> {
    pub fn new() -> PySet<T> {
        PySet { table: (0..MINSIZE).map(|_| None).collect(), used: 0 }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn contains(&self, h: u64, v: &T) -> bool {
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match &self.table[i + j] {
                    None => return false,
                    Some((eh, ev)) if *eh == h && ev == v => return true,
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    /// python `s.add(v)` where `h == hash(v)`.
    pub fn add(&mut self, h: u64, v: T) {
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match &self.table[i + j] {
                    None => {
                        self.table[i + j] = Some((h, v));
                        self.used += 1;
                        // no removals: fill == used
                        if self.used * 5 >= mask * 3 {
                            let minused = if self.used > 50000 { self.used * 2 } else { self.used * 4 };
                            self.resize(minused);
                        }
                        return;
                    }
                    Some((eh, ev)) if *eh == h && *ev == v => return,
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    fn resize(&mut self, minused: usize) {
        let mut newsize = MINSIZE;
        while newsize <= minused {
            newsize <<= 1;
        }
        let old = std::mem::replace(&mut self.table, (0..newsize).map(|_| None).collect());
        let mask = newsize - 1;
        for (h, v) in old.into_iter().flatten() {
            // set_insert_clean
            let mut i = (h as usize) & mask;
            let mut perturb = h;
            let slot = 'outer: loop {
                if self.table[i].is_none() {
                    break i;
                }
                if i + LINEAR_PROBES <= mask {
                    for j in 1..=LINEAR_PROBES {
                        if self.table[i + j].is_none() {
                            break 'outer i + j;
                        }
                    }
                }
                perturb >>= PERTURB_SHIFT;
                i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
            };
            self.table[slot] = Some((h, v));
        }
    }

    /// Elements in python iteration order.
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        self.table.iter().filter_map(|e| e.as_ref().map(|(_, v)| v))
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
}
