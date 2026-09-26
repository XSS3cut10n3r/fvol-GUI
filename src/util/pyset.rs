//! CPython `set` of ints with CPython's exact iteration order.
//!
//! Python iterates a set in hash-table slot order, which for ints (hash = value mod 2^61-1,
//! not randomized) is deterministic but depends on CPython's open-addressing scheme (linear
//! probes + perturbation, resize policy). Plugins that iterate a python `set` of ints (e.g.
//! pstree's children sets) use this to reproduce python's output order byte for byte.
//!
//! Mirrors `Objects/setobject.c` (CPython 3.14): `PySet_MINSIZE` 8, `LINEAR_PROBES` 9,
//! `PERTURB_SHIFT` 5, grow when `fill*5 >= mask*3` to the smallest power of two > `used*4`
//! (`used*2` above 50000 elements). Only insertion is supported (no removal).

const MINSIZE: usize = 8;
const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;

/// python `hash(int)` for a non-negative int (as the unsigned `size_t` CPython indexes with).
#[inline]
pub fn py_int_hash(v: u64) -> u64 {
    const P: u64 = (1 << 61) - 1;
    v % P
}

/// An insertion-only python `set` of non-negative ints.
#[derive(Clone, Debug)]
pub struct PyIntSet {
    /// slots: Some((hash, value))
    table: Vec<Option<(u64, u64)>>,
    used: usize,
}

impl Default for PyIntSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PyIntSet {
    pub fn new() -> PyIntSet {
        PyIntSet { table: vec![None; MINSIZE], used: 0 }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn contains(&self, v: u64) -> bool {
        let h = py_int_hash(v);
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match self.table[i + j] {
                    None => return false,
                    Some((eh, ev)) if eh == h && ev == v => return true,
                    _ => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
        }
    }

    /// python `s.add(v)`.
    pub fn add(&mut self, v: u64) {
        let h = py_int_hash(v);
        let mask = self.table.len() - 1;
        let mut i = (h as usize) & mask;
        let mut perturb = h;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match self.table[i + j] {
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
                    Some((eh, ev)) if eh == h && ev == v => return,
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
        let old = std::mem::replace(&mut self.table, vec![None; newsize]);
        let mask = newsize - 1;
        for (h, v) in old.into_iter().flatten() {
            // set_insert_clean
            let mut i = (h as usize) & mask;
            let mut perturb = h;
            'outer: loop {
                if self.table[i].is_none() {
                    self.table[i] = Some((h, v));
                    break;
                }
                if i + LINEAR_PROBES <= mask {
                    for j in 1..=LINEAR_PROBES {
                        if self.table[i + j].is_none() {
                            self.table[i + j] = Some((h, v));
                            break 'outer;
                        }
                    }
                }
                perturb >>= PERTURB_SHIFT;
                i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & mask;
            }
        }
    }

    /// Elements in python iteration order.
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.table.iter().filter_map(|e| e.map(|(_, v)| v))
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
}
