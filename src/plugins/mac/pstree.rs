//! mac.pstree.PsTree (python `plugins/mac/pstree.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Output order depends on python container semantics: `_processes` / `_levels` /
//! `_children` are insertion-ordered dicts, and each `_children` value is a python `set` of
//! ints iterated in CPython's hash-table order, reproduced by `util::pyset::PySet`.

use crate::context::Context;
use crate::error::Result;
use crate::objects::Obj;
use crate::objects::util::array_to_string;
use crate::plugins::{Config, Plugin};
use crate::renderers::{ColType, Column, RowSink, Value};
use crate::util::FxHashMap;
use crate::util::pyset::{PySet, py_hash_int};

pub struct PsTree;

/// python `set` of ints (CPython slot order); pids are python ints, so negative values too.
type PyIntSet = PySet<i128>;

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
                children.entry(ppid).or_default().add(py_hash_int(cpid), cpid);
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
                    stack.push((children.get(&pid).unwrap_or(&empty).iter().copied().collect(), 0));
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
            s.add(py_hash_int(k), k);
        }
        s.iter().copied().collect()
    }

    #[test]
    fn hash() {
        let h = |v: i128| py_hash_int(v) as i64;
        assert_eq!(h(5), 5);
        assert_eq!(h(-1), -2);
        assert_eq!(h(-2), -2);
        assert_eq!(h((1 << 61) - 1), 0);
        assert_eq!(h(1 << 61), 1);
        assert_eq!(h(-(1 << 61)), -1 - 1);
    }

    /// FNV-1a over the iteration order; the expected values were computed with CPython 3.14
    /// (`list(s)` of a set filled from the same LCG sequence), crossing every resize step and
    /// the 50000-entry growth switch.
    #[test]
    fn set_order_matches_cpython_lcg() {
        let cases: [(u64, usize, u64, bool, usize, u64); 9] = [
            (1, 5, 100, false, 5, 11452854844306586657),
            (2, 17, 1000, false, 17, 17769304224765328006),
            (3, 50, 1000, true, 47, 3592289409714888583),
            (4, 200, 100000, true, 200, 7466873708183751588),
            (5, 1000, 5000, true, 826, 2677121862833066355),
            (6, 3000, 1 << 31, true, 3000, 2243579242009868765),
            (7, 60000, 1 << 40, true, 60000, 9383077065800754809),
            (8, 120000, 200000, false, 90272, 11637013068619461276),
            (9, 40, 40, true, 17, 1230134097121298437),
        ];
        for (seed, n, rng, neg, len, want) in cases {
            let mut x = seed;
            let mut next = || {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                x
            };
            let mut s = PyIntSet::new();
            for _ in 0..n {
                let mut v = (next() % rng) as i128;
                if neg && next() & 1 == 1 {
                    v = -v;
                }
                s.add(py_hash_int(v), v);
            }
            assert_eq!(s.len(), len);
            let mut h: u64 = 0xcbf29ce484222325;
            for &v in s.iter() {
                for b in (v as i64 as u64).to_le_bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
            }
            assert_eq!(h, want, "seed {seed}");
        }
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
