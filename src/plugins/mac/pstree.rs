//! mac.pstree.PsTree (python `plugins/mac/pstree.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Output order depends on python container semantics: `_processes` / `_levels` /
//! `_children` are insertion-ordered dicts, and each `_children` value is a python `set` of
//! ints iterated in CPython's hash-table order, reproduced by [`PyIntSet`].

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::util::FxHashMap;

pub struct PsTree;

/// python `hash(int)`: `sign * (|v| mod (2**61 - 1))`, with -1 mapped to -2.
pub fn py_hash_int(v: i128) -> i64 {
    const P: u128 = (1 << 61) - 1;
    let h = (v.unsigned_abs() % P) as i64;
    let h = if v < 0 { -h } else { h };
    if h == -1 { -2 } else { h }
}

/// A CPython `set` of python ints with CPython's exact slot layout, so iteration order matches
/// (`Objects/setobject.c`: open addressing over a power-of-two table (min 8), probing 9
/// following slots linearly (`LINEAR_PROBES`) before perturbing `i = i*5 + 1 + (perturb >>=
/// 5)`; after an insert with `fill*5 >= mask*3` the table is rebuilt at the smallest power of
/// two > `used*4` (`used*2` past 50000 entries), re-inserting in old slot order). Insert-only
/// (no deletions, so no dummies), which is all pstree needs.
#[derive(Clone, Debug)]
pub struct PyIntSet {
    /// slot -> (hash, key)
    table: Vec<Option<(i64, i128)>>,
    fill: usize,
}

const LINEAR_PROBES: usize = 9;
const PERTURB_SHIFT: u32 = 5;

impl Default for PyIntSet {
    fn default() -> Self {
        PyIntSet { table: vec![None; 8], fill: 0 }
    }
}

impl PyIntSet {
    pub fn new() -> PyIntSet {
        PyIntSet::default()
    }

    /// python `set.add(key)`.
    pub fn add(&mut self, key: i128) {
        let hash = py_hash_int(key);
        let mask = self.table.len() - 1;
        let mut perturb = hash as u64 as usize;
        let mut i = perturb & mask;
        loop {
            let probes = if i + LINEAR_PROBES <= mask { LINEAR_PROBES } else { 0 };
            for j in 0..=probes {
                match self.table[i + j] {
                    None => {
                        self.table[i + j] = Some((hash, key));
                        self.fill += 1;
                        if self.fill * 5 >= mask * 3 {
                            let used = self.fill;
                            self.resize(if used > 50000 { used * 2 } else { used * 4 });
                        }
                        return;
                    }
                    Some((h, k)) if h == hash && k == key => return,
                    Some(_) => {}
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
        }
    }

    /// `set_table_resize(so, minused)` + `set_insert_clean` for every entry in slot order.
    fn resize(&mut self, minused: usize) {
        let mut newsize = 8usize;
        while newsize <= minused {
            newsize <<= 1;
        }
        let old = std::mem::replace(&mut self.table, vec![None; newsize]);
        let mask = newsize - 1;
        for (hash, key) in old.into_iter().flatten() {
            let mut perturb = hash as u64 as usize;
            let mut i = perturb & mask;
            'probe: loop {
                if self.table[i].is_none() {
                    self.table[i] = Some((hash, key));
                    break;
                }
                if i + LINEAR_PROBES <= mask {
                    for j in 1..=LINEAR_PROBES {
                        if self.table[i + j].is_none() {
                            self.table[i + j] = Some((hash, key));
                            break 'probe;
                        }
                    }
                }
                perturb >>= PERTURB_SHIFT;
                i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb)) & mask;
            }
        }
    }

    /// Iteration order (python `for x in s`).
    pub fn iter(&self) -> impl Iterator<Item = i128> + '_ {
        self.table.iter().filter_map(|e| e.map(|(_, k)| k))
    }

    pub fn len(&self) -> usize {
        self.fill
    }

    pub fn is_empty(&self) -> bool {
        self.fill == 0
    }
}

/// python's default recursion limit, minus the frames below `yield_processes` (vol.py, CLI,
/// renderer, TreeGrid.populate, `_generator`): only a 2-cycle of parent pids (A.ppid == B,
/// B.ppid == A) recurses forever and ends in a RecursionError.
const MAX_DEPTH: usize = 1000 - 20;

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "mac.pstree.PsTree"
    }
    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }
    fn run(&self, ctx: &Context, _cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let k = ctx.mac_kernel()?;
        out.begin(vec![Column::new("PID", ColType::Int), Column::new("PPID", ColType::Int), Column::new("COMM", ColType::Str)])?;
        // self._processes: pid -> proc (insertion ordered; a repeated pid keeps its slot)
        let mut order: Vec<i128> = Vec::new();
        let mut procs: FxHashMap<i128, (Obj, i128)> = FxHashMap::default(); // pid -> (proc, p_ppid)
        for p in super::pslist::list_tasks(k, "tasks", &|_| Ok(false)) {
            let p = p?;
            let pid = p.m("p_pid")?.int()?;
            if !procs.contains_key(&pid) {
                order.push(pid);
            }
            procs.insert(pid, (p, 0));
        }
        // _find_level for every pid, in dict order
        let mut levels: FxHashMap<i128, usize> = FxHashMap::default();
        let mut children: FxHashMap<i128, PyIntSet> = FxHashMap::default();
        let mut ppid_cache: FxHashMap<i128, i128> = FxHashMap::default();
        let n = order.len();
        for &pid in &order {
            let mut level = 0usize;
            let mut cur = procs.get(&pid).map(|e| (pid, e.0));
            while let Some((cpid, proc)) = cur {
                if proc.addr == 0 {
                    break;
                }
                let ppid = match ppid_cache.get(&cpid) {
                    Some(&v) => v,
                    None => {
                        let v = proc.m("p_ppid")?.int()?;
                        ppid_cache.insert(cpid, v);
                        v
                    }
                };
                if ppid == 0 || ppid == pid {
                    break;
                }
                children.entry(ppid).or_default().add(cpid);
                cur = procs.get(&ppid).map(|e| (ppid, e.0));
                level += 1;
                // a parent cycle not through `pid`: python loops forever here
                if level > n {
                    break;
                }
            }
            levels.insert(pid, level);
        }
        for (pid, e) in procs.iter_mut() {
            e.1 = ppid_cache.get(pid).copied().unwrap_or(0);
        }
        // yield_processes, depth-first with an explicit stack
        let row = |pid: i128| -> Result<(usize, Vec<Value>)> {
            let (proc, _) = procs[&pid];
            let p_pid = proc.m("p_pid")?.int()?;
            let p_ppid = proc.m("p_ppid")?.int()?;
            let comm = array_to_string(&proc.m("p_comm")?, None)?;
            let depth = levels[&pid].saturating_sub(1);
            Ok((depth, vec![Value::Int(p_pid), Value::Int(p_ppid), Value::Str(comm)]))
        };
        let empty = PyIntSet::new();
        for &top in &order {
            if levels[&top] != 1 {
                continue;
            }
            // stack of (children of a yielded pid, next index)
            let mut stack: Vec<(Vec<i128>, usize)> = Vec::new();
            let mut next = Some(top);
            loop {
                if let Some(pid) = next.take() {
                    if stack.len() >= MAX_DEPTH {
                        panic!("RecursionError: maximum recursion depth exceeded");
                    }
                    let (depth, values) = row(pid)?;
                    out.row(depth, values)?;
                    stack.push((children.get(&pid).unwrap_or(&empty).iter().collect(), 0));
                }
                let Some((kids, i)) = stack.last_mut() else { break };
                if *i < kids.len() {
                    next = Some(kids[*i]);
                    *i += 1;
                } else {
                    stack.pop();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(keys: &[i128]) -> Vec<i128> {
        let mut s = PyIntSet::new();
        for &k in keys {
            s.add(k);
        }
        s.iter().collect()
    }

    #[test]
    fn hash() {
        assert_eq!(py_hash_int(5), 5);
        assert_eq!(py_hash_int(-1), -2);
        assert_eq!(py_hash_int(-2), -2);
        assert_eq!(py_hash_int((1 << 61) - 1), 0);
        assert_eq!(py_hash_int(1 << 61), 1);
        assert_eq!(py_hash_int(-(1 << 61)), -1 - 1);
    }

    #[test]
    fn set_order_matches_cpython() {
        // list(set) after these insertions, from CPython 3.14
        assert_eq!(
            order(&[391, 264, 272, 273, 536, 537, 538, 293, 306, 311, 312, 189, 190, 317, 319, 193, 195, 197, 328, 203]),
            vec![391, 264, 272, 273, 536, 537, 538, 293, 306, 311, 312, 317, 189, 190, 319, 193, 195, 197, 328, 203]
        );
    }
}
