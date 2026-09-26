//! timeliner.Timeliner (python `plugins/timeliner.py`).
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! Runs every plugin implementing `generate_timeline` (python `TimeLinerInterface`
//! subclasses, in python's class order) and merges their events exactly like python,
//! including its quirks:
//!   * events are collected in a dict keyed by (plugin class name, description) -> {type: time};
//!     two plugins with the same class name (`windows.threads.Threads` and
//!     `windows.orphan_kernel_threads.Threads`) share entries;
//!   * after EACH plugin that ran without raising, the WHOLE dict is appended to the result
//!     again (entries of the first plugin appear once per later plugin), and every appended
//!     row carries the times of python's loop variable `times` -- the dict of the last event
//!     generated so far, or with `--create-bodyfile` the previous entry of the loop -- not its
//!     own;
//!   * a plugin raising midway keeps the events yielded so far but skips its append pass;
//!   * rows are stable-sorted by (created, modified, accessed, changed) with absent values as
//!     `datetime(9999, 12, 1, tzinfo=utc)`;
//!   * the body file (`volatility.body`) gets one line per entry per pass, written while the
//!     plugins run; `_any_time_present` treats a MISSING type as present (python passes the
//!     `NotApplicableValue` class, not an instance, as the default).
//!
//! The plugins themselves run concurrently (their results are merged in python order), rows
//! are 8 bytes (entry, times snapshot) and sorted by a counting sort over snapshot ranks.

use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement, TimeKind, TimelineBatch, TimelineEvent, TimelineTime};
use crate::renderers::{ColType, Column, DateTime, RowSink, Value};
use crate::util::FxHashMap;
use std::io::Write;

pub struct Timeliner;

/// python `framework.class_subclasses(TimeLinerInterface)` in class order (CLI names).
pub const TIMELINER_PLUGINS: [&str; 22] = [
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "linux.pslist.PsList",
    "linux.bash.Bash",
    "linux.boottime.Boottime",
    "linux.lsof.Lsof",
    "linux.pagecache.Files",
    "mac.bash.Bash",
    "windows.registry.amcache.Amcache",
    "windows.thrdscan.ThrdScan",
    "windows.threads.Threads",
    "windows.orphan_kernel_threads.Threads",
    "windows.dlllist.DllList",
    "windows.mftscan.MFTScan",
    "windows.netscan.NetScan",
    "windows.netstat.NetStat",
    "windows.registry.scheduled_tasks.ScheduledTasks",
    "windows.sessions.Sessions",
    "windows.shimcachemem.ShimcacheMem",
    "windows.symlinkscan.SymlinkScan",
    "windows.unloadedmodules.UnloadedModules",
    "windows.registry.userassist.UserAssist",
];

/// A time cell (compact form of the `Value`s plugins yield).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Tv {
    /// type not generated for this entry (`times.get(t, NotApplicableValue())`)
    Missing,
    Dt(DateTime),
    NotApplicable,
    Unreadable,
    Unparsable,
    NotAvailable,
    /// any other value (index into `Merge::others`); python would fail to sort it
    Other(u32),
}

impl Tv {
    fn is_absent(self) -> bool {
        !matches!(self, Tv::Dt(_) | Tv::Other(_))
    }
}

/// python `_sort_function` key element: absent -> 9999-12-01 00:00:00 UTC.
const MAX_DATE_SECS: i64 = 253_399_622_400;

/// One element of python's sort key, by comparability class (python raises `TypeError` for
/// `<` across classes, where `==` is False). Microseconds since the epoch for datetimes,
/// `Merge::others` indices for strings / bytes / unknown objects.
#[derive(Clone, Copy, Debug)]
enum SortElem {
    Aware(i128),
    Naive(i128),
    None,
    /// int / bool / float as (floor, fraction)
    Num(i128, f64),
    Str(u32),
    Bytes(u32),
    /// any other object: only equal to itself, never ordered
    Unknown(u32),
}

impl SortElem {
    fn class(self) -> u8 {
        match self {
            SortElem::Aware(_) => 0,
            SortElem::Naive(_) => 1,
            SortElem::None => 2,
            SortElem::Num(..) => 3,
            SortElem::Str(_) => 4,
            SortElem::Bytes(_) => 5,
            SortElem::Unknown(_) => 6,
        }
    }

    /// python `type(x).__name__` as the comparison errors print it.
    fn type_name(self) -> &'static str {
        match self {
            SortElem::Aware(_) | SortElem::Naive(_) => "datetime.datetime",
            SortElem::None => "NoneType",
            SortElem::Num(..) => "int",
            SortElem::Str(_) => "str",
            SortElem::Bytes(_) => "bytes",
            SortElem::Unknown(_) => "object",
        }
    }
}

fn kind_index(k: TimeKind) -> usize {
    match k {
        TimeKind::Created => 0,
        TimeKind::Modified => 1,
        TimeKind::Accessed => 2,
        TimeKind::Changed => 3,
    }
}

/// python `int(dt.timestamp())` for an aware datetime: the correctly rounded float of
/// `total_microseconds / 10**6`, truncated toward zero.
fn py_int_timestamp(dt: &DateTime) -> i64 {
    let n = dt.secs as i128 * 1_000_000 + dt.micros as i128;
    let d: u128 = 1_000_000;
    let a = n.unsigned_abs();
    let f = if a < (1u128 << 53) {
        a as f64 / d as f64
    } else {
        let q0 = a / d;
        let bits = 128 - q0.leading_zeros() as i32;
        let shift = 53 - bits;
        let (mut m, rem, den) = if shift >= 0 {
            let num = a << shift;
            (num / d, num % d, d)
        } else {
            let den = d << (-shift);
            (a / den, a % den, den)
        };
        let twice = rem * 2;
        if twice > den || (twice == den && m & 1 == 1) {
            m += 1;
        }
        m as f64 * 2f64.powi(-shift)
    };
    let f = if n < 0 { -f } else { f };
    f.trunc() as i64
}

/// python `str(value)` of the (non-datetime) values a plugin might yield as a timestamp.
fn py_str(v: &Value) -> String {
    match v {
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::SStr(s) => s.to_string(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_string(),
        Value::Float(f) => {
            let mut o = Vec::new();
            crate::renderers::pyfmt::push_float(&mut o, *f);
            String::from_utf8_lossy(&o).into_owned()
        }
        Value::Bytes(b) => {
            let mut o = Vec::new();
            crate::renderers::pyfmt::push_bytes_repr(&mut o, b);
            String::from_utf8_lossy(&o).into_owned()
        }
        _ => "0".to_string(),
    }
}

struct Entry {
    class: u16,
    desc: &'static str,
    times: [Tv; 4],
    /// snapshot id of `times` (valid unless `dirty`)
    snap: u32,
    dirty: bool,
}

/// python's `_generator` state.
#[derive(Default)]
struct Merge {
    classes: Vec<&'static str>,
    entries: Vec<Entry>,
    index: FxHashMap<(u16, &'static str), u32>,
    snaps: Vec<[Tv; 4]>,
    others: Vec<Value>,
    /// python's loop variable `times` (an entry)
    cur: Option<u32>,
    rows: Vec<(u32, u32)>,
    /// per class: entries added by `add_bulk` are missing from `index`
    stale: Vec<bool>,
}

/// The compact cell of a set timeline time.
fn tv_of(t: TimelineTime) -> Tv {
    match t {
        TimelineTime::DateTime(dt) => Tv::Dt(dt),
        TimelineTime::NotApplicable => Tv::NotApplicable,
        TimelineTime::Unreadable => Tv::Unreadable,
        TimelineTime::Unparsable => Tv::Unparsable,
        TimelineTime::NotAvailable => Tv::NotAvailable,
        TimelineTime::Unset => Tv::Missing,
    }
}

/// Plugins yielding at least this many events are merged by the parallel `add_bulk`.
const BULK_MIN: usize = 1 << 16;

impl Merge {
    /// Put the entries of `class` that `add_bulk` added into `index`.
    fn refresh_index(&mut self, class: u16) {
        if !self.stale.get(class as usize).copied().unwrap_or(false) {
            return;
        }
        for (i, e) in self.entries.iter().enumerate() {
            if e.class == class {
                self.index.insert((class, e.desc), i as u32);
            }
        }
        self.stale[class as usize] = false;
    }

    /// All events of one plugin, in order (`add_event` for each).
    fn add_events(&mut self, class: u16, batches: Vec<TimelineBatch>) {
        let n: usize = batches.iter().map(|b| b.len()).sum();
        if n >= BULK_MIN {
            return self.add_bulk(class, batches);
        }
        self.refresh_index(class);
        for b in batches {
            for ev in b.into_events() {
                self.add_event(class, ev);
            }
        }
    }

    /// `add_event` for every event, in parallel: only the plugin's end state matters (entries
    /// in first-occurrence order, the last value set per time type, `cur` = the last event's
    /// entry; snapshots are only taken by `pass`). Groups of consecutive same-description
    /// events are sharded by description hash, each shard reduced on its own thread, then the
    /// new entries appended in first-occurrence order.
    fn add_bulk(&mut self, class: u16, mut batches: Vec<TimelineBatch>) {
        const SHARDS: usize = 64;
        const UNIT: usize = 1 << 16;
        if self.stale.len() <= class as usize {
            self.stale.resize(class as usize + 1, false);
        }
        let has_old = self.entries.iter().any(|e| e.class == class);
        if has_old {
            self.refresh_index(class);
        }
        let shard_of = |d: &str| (crate::util::fxhash::hash_bytes(d.as_bytes()) >> 58) as usize;
        let has_times = |t: &[TimelineTime; 4]| t.iter().any(|x| *x != TimelineTime::Unset);
        // work units of at most 64k events / groups: (batch, start, end)
        let mut units: Vec<(u32, u32, u32)> = Vec::new();
        for (b, v) in batches.iter().enumerate() {
            let len = match v {
                TimelineBatch::Events(e) => e.len(),
                TimelineBatch::Groups(g) => g.groups.len(),
            };
            let mut s = 0;
            while s < len {
                let e = (s + UNIT).min(len);
                units.push((b as u32, s as u32, e as u32));
                s = e;
            }
        }
        // position of the plugin's last event: (batch, event index / group index)
        let last_pos = batches.iter().enumerate().rev().find_map(|(b, v)| match v {
            TimelineBatch::Events(e) => (!e.is_empty()).then(|| (b as u32, e.len() as u32 - 1)),
            TimelineBatch::Groups(g) => g.groups.iter().rposition(|x| has_times(&x.1)).map(|i| (b as u32, i as u32)),
        });
        // 1. per unit and shard: groups as (start, count); events: consecutive events with the
        //    same description (an entry's events come back to back), groups: (index, 0)
        let parts: Vec<Vec<Vec<(u32, u32)>>> = crate::util::par::par_map(units.len(), |u| {
            let (b, s, e) = units[u];
            let mut v = vec![Vec::new(); SHARDS];
            match &batches[b as usize] {
                TimelineBatch::Events(evs) => {
                    let mut i = s;
                    while i < e {
                        let d = &evs[i as usize].description;
                        let mut j = i + 1;
                        while j < e && evs[j as usize].description == *d {
                            j += 1;
                        }
                        v[shard_of(d)].push((i, j - i));
                        i = j;
                    }
                }
                TimelineBatch::Groups(g) => {
                    for i in s..e {
                        if has_times(&g.groups[i as usize].1) {
                            v[shard_of(g.desc(i as usize))].push((i, 0));
                        }
                    }
                }
            }
            v
        });
        // 2. per shard: distinct new descriptions (first position, values), and the values set
        //    on existing entries; non-date event values are resolved later (`Tv::Other(k)` = the
        //    k-th position in `other`)
        struct Shard {
            first: Vec<(u32, u32)>,
            times: Vec<[Tv; 4]>,
            old: Vec<(u32, [Tv; 4])>,
            other: Vec<(u32, u32)>,
            /// local id / existing entry of the plugin's last event (if in this shard)
            last: Option<std::result::Result<u32, u32>>,
        }
        let index = &self.index;
        let shards: Vec<Shard> = crate::util::par::par_map(SHARDS, |s| {
            let mut map: FxHashMap<&str, u32> = FxHashMap::default();
            let mut old: FxHashMap<u32, [Tv; 4]> = FxHashMap::default();
            let mut sh = Shard { first: Vec::new(), times: Vec::new(), old: Vec::new(), other: Vec::new(), last: None };
            for (u, &(b, _, _)) in units.iter().enumerate() {
                let batch = &batches[b as usize];
                for &(i, c) in &parts[u][s] {
                    let d = match batch {
                        TimelineBatch::Events(evs) => evs[i as usize].description.as_str(),
                        TimelineBatch::Groups(g) => g.desc(i as usize),
                    };
                    let g = if has_old { index.get(&(class, d)).copied() } else { None };
                    let (id, t) = match g {
                        Some(g) => (Err(g), old.entry(g).or_insert([Tv::Missing; 4])),
                        None => {
                            let id = *map.entry(d).or_insert_with(|| {
                                sh.first.push((b, i));
                                sh.times.push([Tv::Missing; 4]);
                                sh.first.len() as u32 - 1
                            });
                            (Ok(id), &mut sh.times[id as usize])
                        }
                    };
                    let is_last = match batch {
                        TimelineBatch::Events(evs) => {
                            for j in i..i + c {
                                let ev = &evs[j as usize];
                                t[kind_index(ev.kind)] = match TimelineTime::from_value(&ev.time) {
                                    Some(x) => tv_of(x),
                                    None => {
                                        sh.other.push((b, j));
                                        Tv::Other(sh.other.len() as u32 - 1)
                                    }
                                };
                            }
                            last_pos.is_some_and(|(lb, li)| lb == b && (i..i + c).contains(&li))
                        }
                        TimelineBatch::Groups(g) => {
                            for (k, x) in g.groups[i as usize].1.iter().enumerate() {
                                if *x != TimelineTime::Unset {
                                    t[kind_index(g.order[k])] = tv_of(*x);
                                }
                            }
                            last_pos == Some((b, i))
                        }
                    };
                    if is_last {
                        sh.last = Some(id);
                    }
                }
            }
            let mut o: Vec<(u32, [Tv; 4])> = old.into_iter().collect();
            o.sort_unstable_by_key(|x| x.0);
            sh.old = o;
            sh
        });
        drop(parts);
        // 3. new entries in first-occurrence order; their descriptions in one arena
        let mut order: Vec<(u64, u32, u32)> = Vec::new();
        for (s, sh) in shards.iter().enumerate() {
            for (j, &(b, i)) in sh.first.iter().enumerate() {
                order.push((((b as u64) << 32) | i as u64, s as u32, j as u32));
            }
        }
        order.sort_unstable_by_key(|x| x.0);
        let desc_at = |pos: u64| -> &str {
            let (b, i) = ((pos >> 32) as usize, pos as u32 as usize);
            match &batches[b] {
                TimelineBatch::Events(evs) => &evs[i].description,
                TimelineBatch::Groups(g) => g.desc(i),
            }
        };
        let total: usize = order.iter().map(|x| desc_at(x.0).len()).sum();
        let mut arena = String::with_capacity(total);
        for x in &order {
            arena.push_str(desc_at(x.0));
        }
        let arena: &'static str = arena.leak();
        let base = self.entries.len() as u32;
        let mut gid: Vec<Vec<u32>> = shards.iter().map(|sh| vec![0; sh.first.len()]).collect();
        self.entries.reserve(order.len());
        let mut at = 0;
        for (k, &(pos, s, j)) in order.iter().enumerate() {
            gid[s as usize][j as usize] = base + k as u32;
            let n = desc_at(pos).len();
            let desc = &arena[at..at + n];
            at += n;
            self.entries.push(Entry { class, desc, times: shards[s as usize].times[j as usize], snap: 0, dirty: true });
        }
        // 4. existing entries' new values; non-date values
        let mut resolve = |m: &mut Merge, sh: &Shard, t: &mut [Tv; 4]| {
            for v in t.iter_mut() {
                if let Tv::Other(k) = *v {
                    let (b, i) = sh.other[k as usize];
                    if let TimelineBatch::Events(evs) = &mut batches[b as usize] {
                        *v = m.tv(std::mem::replace(&mut evs[i as usize].time, Value::NotApplicable));
                    }
                }
            }
        };
        for (s, sh) in shards.iter().enumerate() {
            if !sh.other.is_empty() {
                for &g in &gid[s] {
                    let mut t = self.entries[g as usize].times;
                    resolve(self, sh, &mut t);
                    self.entries[g as usize].times = t;
                }
            }
            for &(g, mut t) in &sh.old {
                resolve(self, sh, &mut t);
                let e = &mut self.entries[g as usize];
                for (k, v) in t.into_iter().enumerate() {
                    if v != Tv::Missing {
                        e.times[k] = v;
                    }
                }
                e.dirty = true;
            }
        }
        if let Some((s, id)) = shards.iter().enumerate().find_map(|(s, sh)| sh.last.map(|id| (s, id))) {
            self.cur = Some(match id {
                Ok(j) => gid[s][j as usize],
                Err(g) => g,
            });
        }
        self.stale[class as usize] = true;
        // freeing millions of strings is off the critical path
        std::thread::spawn(move || drop(batches));
    }

    fn tv(&mut self, v: Value) -> Tv {
        match v {
            Value::DateTime(dt) => Tv::Dt(dt),
            Value::NotApplicable => Tv::NotApplicable,
            Value::Unreadable => Tv::Unreadable,
            Value::Unparsable => Tv::Unparsable,
            Value::NotAvailable => Tv::NotAvailable,
            v => {
                self.others.push(v);
                Tv::Other(self.others.len() as u32 - 1)
            }
        }
    }

    fn add_event(&mut self, class: u16, ev: TimelineEvent) {
        // plugins yield an entry's events back to back (MFT records: 4 per description): the
        // previous event's entry is the common hit, without hashing / probing the big index
        let prev = self.cur.filter(|&i| {
            let e = &self.entries[i as usize];
            e.class == class && e.desc == ev.description
        });
        let k = (class, ev.description.as_str());
        let idx = match prev.or_else(|| self.index.get(&k).copied()) {
            Some(i) => i,
            None => {
                let desc: &'static str = ev.description.leak();
                let i = self.entries.len() as u32;
                self.entries.push(Entry { class, desc, times: [Tv::Missing; 4], snap: 0, dirty: true });
                self.index.insert((class, desc), i);
                i
            }
        };
        let tv = self.tv(ev.time);
        let e = &mut self.entries[idx as usize];
        e.times[kind_index(ev.kind)] = tv;
        e.dirty = true;
        self.cur = Some(idx);
    }

    fn snap_of(&mut self, i: u32) -> u32 {
        let e = &mut self.entries[i as usize];
        if e.dirty {
            self.snaps.push(e.times);
            e.snap = self.snaps.len() as u32 - 1;
            e.dirty = false;
        }
        e.snap
    }

    /// One append pass (python's `for plugin_name, item in self.timeline:` loop).
    fn pass(&mut self, body: &mut Option<std::io::BufWriter<std::fs::File>>) -> Result<()> {
        for j in 0..self.entries.len() as u32 {
            let t = match self.cur {
                Some(t) => t,
                None => return Ok(()),
            };
            let s = self.snap_of(t);
            self.rows.push((j, s));
            if let Some(w) = body.as_mut() {
                self.cur = Some(j);
                self.body_line(j, w)?;
            }
        }
        Ok(())
    }

    fn body_line(&self, j: u32, w: &mut std::io::BufWriter<std::fs::File>) -> Result<()> {
        let e = &self.entries[j as usize];
        // _any_time_present: a missing type counts as present
        if !e.times.iter().any(|t| *t == Tv::Missing || !t.is_absent()) {
            return Ok(());
        }
        let fmt = |t: Tv| -> String {
            match t {
                Tv::Dt(dt) => py_int_timestamp(&dt).to_string(),
                Tv::Other(i) => py_str(&self.others[i as usize]),
                _ => "0".to_string(),
            }
        };
        writeln!(
            w,
            "|{} - {}|0|0|0|0|0|{}|{}|{}|{}",
            self.classes[e.class as usize],
            e.desc.replace('|', "_"),
            fmt(e.times[2]),
            fmt(e.times[1]),
            fmt(e.times[3]),
            fmt(e.times[0])
        )?;
        Ok(())
    }

    /// python `sorted(data, key=self._sort_function)`: row order, or python's `TypeError`.
    ///
    /// Key elements python cannot order against each other (None or other non-datetime values
    /// yielded as timestamps, naive vs aware datetimes) make the sort raise exactly when two
    /// keys first differ at such a pair: any comparison sort has to compare one such pair
    /// (ordering those classes one way or the other would otherwise give it the same trace
    /// and the same, then necessarily wrong, output). Without such a pair python's result is
    /// the stable sort by any total order that agrees with python's `<` within each class.
    fn sorted_rows(&self) -> Result<Vec<(u32, u32)>> {
        if self.rows.len() < 2 {
            return Ok(self.rows.clone());
        }
        let general = self.snaps.iter().any(|s| s.iter().any(|t| matches!(t, Tv::Other(_) | Tv::Dt(DateTime { utc: false, .. }))));
        let (order, same): (Vec<u32>, Box<dyn Fn(u32, u32) -> bool + '_>) = if general {
            let keys: Vec<[SortElem; 4]> = self.snaps.iter().map(|s| s.map(|t| self.sort_elem(t))).collect();
            let cmp = |a: u32, b: u32| {
                let (ka, kb) = (&keys[a as usize], &keys[b as usize]);
                (0..4).map(|i| self.elem_cmp(ka[i], kb[i])).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal)
            };
            let mut order: Vec<u32> = (0..keys.len() as u32).collect();
            order.sort_unstable_by(|&a, &b| cmp(a, b));
            // python's error for `ka < kb` (None when python can compare the two keys)
            let error = |a: u32, b: u32| -> Option<String> {
                let (ka, kb) = (&keys[a as usize], &keys[b as usize]);
                let i = (0..4).find(|&i| self.elem_cmp(ka[i], kb[i]).is_ne())?;
                self.incomparable(ka[i], kb[i])
            };
            if order.windows(2).any(|w| error(w[0], w[1]).is_some()) {
                // (stderr only) the first comparison count_run makes: an element against the
                // one before it
                let msg = self.rows.windows(2).find_map(|w| error(w[1].1, w[0].1));
                return Err(Error::msg(msg.or_else(|| order.windows(2).find_map(|w| error(w[1], w[0]))).unwrap_or_default()));
            }
            (order, Box::new(move |a, b| (0..4).all(|i| self.elem_cmp(keys[a as usize][i], keys[b as usize][i]).is_eq())))
        } else {
            // the common case: aware datetimes and absent values (= python's max_date) only
            let key = |t: Tv| -> (i64, u32) {
                match t {
                    Tv::Dt(dt) => (dt.secs, dt.micros),
                    _ => (MAX_DATE_SECS, 0),
                }
            };
            let keys: Vec<[(i64, u32); 4]> = self.snaps.iter().map(|s| s.map(key)).collect();
            let mut order: Vec<u32> = (0..keys.len() as u32).collect();
            order.sort_unstable_by(|&a, &b| keys[a as usize].cmp(&keys[b as usize]));
            (order, Box::new(move |a, b| keys[a as usize] == keys[b as usize]))
        };
        let mut rank = vec![0u32; self.snaps.len()];
        let mut r = 0u32;
        for (i, &s) in order.iter().enumerate() {
            if i > 0 && !same(s, order[i - 1]) {
                r += 1;
            }
            rank[s as usize] = r;
        }
        // stable counting sort by rank
        let nr = r as usize + 1;
        let mut start = vec![0u32; nr + 1];
        for &(_, s) in &self.rows {
            start[rank[s as usize] as usize + 1] += 1;
        }
        for i in 0..nr {
            start[i + 1] += start[i];
        }
        let mut out = vec![(0u32, 0u32); self.rows.len()];
        for &row in &self.rows {
            let k = rank[row.1 as usize] as usize;
            out[start[k] as usize] = row;
            start[k] += 1;
        }
        Ok(out)
    }

    /// python's `_sort_function` element of a cell (absent values -> the aware max_date).
    fn sort_elem(&self, t: Tv) -> SortElem {
        match t {
            Tv::Dt(dt) if dt.utc => SortElem::Aware(dt.secs as i128 * 1_000_000 + dt.micros as i128),
            Tv::Dt(dt) => SortElem::Naive(dt.secs as i128 * 1_000_000 + dt.micros as i128),
            Tv::Other(i) => match &self.others[i as usize] {
                Value::None => SortElem::None,
                Value::Int(v) => SortElem::Num(*v, 0.0),
                Value::Bool(b) => SortElem::Num(*b as i128, 0.0),
                // exact int/float ordering: (floor, fraction)
                Value::Float(f) if f.is_finite() => SortElem::Num(f.floor() as i128, f - f.floor()),
                Value::Float(f) if *f > 0.0 => SortElem::Num(i128::MAX, 0.0),
                Value::Float(f) if *f < 0.0 => SortElem::Num(i128::MIN, 0.0),
                Value::Str(_) | Value::SStr(_) => SortElem::Str(i),
                Value::Bytes(_) => SortElem::Bytes(i),
                _ => SortElem::Unknown(i),
            },
            _ => SortElem::Aware(MAX_DATE_SECS as i128 * 1_000_000),
        }
    }

    /// A total order agreeing with python's `<` / `==` within each [`SortElem`] class (classes
    /// in declaration order).
    fn elem_cmp(&self, a: SortElem, b: SortElem) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let s = |i: u32| -> &[u8] {
            match &self.others[i as usize] {
                Value::Str(v) => v.as_bytes(),
                Value::SStr(v) => v.as_bytes(),
                Value::Bytes(v) => v,
                _ => &[],
            }
        };
        match (a, b) {
            (SortElem::Aware(x), SortElem::Aware(y)) | (SortElem::Naive(x), SortElem::Naive(y)) => x.cmp(&y),
            (SortElem::None, SortElem::None) => Ordering::Equal,
            (SortElem::Num(x, fx), SortElem::Num(y, fy)) => x.cmp(&y).then(fx.partial_cmp(&fy).unwrap_or(Ordering::Equal)),
            // python str order is code point order = UTF-8 byte order
            (SortElem::Str(x), SortElem::Str(y)) | (SortElem::Bytes(x), SortElem::Bytes(y)) => s(x).cmp(s(y)),
            (SortElem::Unknown(x), SortElem::Unknown(y)) => x.cmp(&y),
            _ => a.class().cmp(&b.class()),
        }
    }

    /// python's error for `a < b` on two unequal key elements it cannot order (None when it
    /// can order them).
    fn incomparable(&self, a: SortElem, b: SortElem) -> Option<String> {
        match (a, b) {
            (SortElem::Aware(_), SortElem::Naive(_)) | (SortElem::Naive(_), SortElem::Aware(_)) => {
                Some("TypeError: can't compare offset-naive and offset-aware datetimes".into())
            }
            _ if a.class() != b.class() || matches!(a, SortElem::Unknown(_)) => {
                Some(format!("TypeError: '<' not supported between instances of '{}' and '{}'", a.type_name(), b.type_name()))
            }
            _ => None,
        }
    }

    fn cell(&self, t: Tv) -> Value {
        match t {
            Tv::Missing | Tv::NotApplicable => Value::NotApplicable,
            Tv::Dt(dt) => Value::DateTime(dt),
            Tv::Unreadable => Value::Unreadable,
            Tv::Unparsable => Value::Unparsable,
            Tv::NotAvailable => Value::NotAvailable,
            Tv::Other(i) => self.others[i as usize].clone(),
        }
    }
}

/// The timeliner plugins to run: python class order, registered, `--plugin-filter`
/// (`filter in plugin_class.__module__ + "." + plugin_class.__name__`).
pub fn usable_plugins(filter: &[String]) -> Vec<&'static dyn Plugin> {
    let all = crate::plugins::all();
    TIMELINER_PLUGINS
        .iter()
        .filter(|n| {
            let full = format!("volatility3.plugins.{n}");
            filter.is_empty() || filter.iter().any(|f| full.contains(f.as_str()))
        })
        .filter_map(|n| all.iter().find(|p| p.name() == *n).copied())
        .collect()
}

/// `--record-config`: python writes `config.json` (`json.dump(total_config, sort_keys=True,
/// indent=2)`) with every constructed plugin's `build_configuration()` under `<Class>.`. The
/// plugins run with their defaults and with timeliner's (generic) stacker choice.
fn record_config(ctx: &Context, plugins: &[&'static dyn Plugin]) -> Result<()> {
    use crate::cli::json::Json;
    let mut items: super::pyconfig::Items = Vec::new();
    let defaults = crate::plugins::Config::default();
    for p in plugins {
        let class = p.name().rsplit('.').next().unwrap_or("");
        for (k, v) in super::pyconfig::plugin_configuration(ctx, p.name(), &defaults, true)? {
            items.push((format!("{class}.{k}"), v));
        }
    }
    let (mut f, _) = ctx.create_output_file("config.json")?;
    f.write_all(Json::Obj(items).dump(Some(2)).as_bytes())?;
    Ok(())
}

/// A plugin's timeline events and the error it raised (if any).
type Ran = (Vec<TimelineBatch>, Option<Error>);
type Outcome = Option<Ran>;

/// Run the plugins' timelines concurrently; a panicking plugin is python's `except Exception`.
fn run_all(ctx: &Context, plugins: &[&'static dyn Plugin]) -> Vec<Outcome> {
    std::thread::scope(|s| {
        let handles: Vec<_> = plugins
            .iter()
            .map(|p| {
                let p = *p;
                s.spawn(move || {
                    let mut cfg = crate::plugins::default_config(p);
                    // python picks the stackers by the CLI plugin's category: "timeliner"
                    // excludes no OS stacker (see mftscan::ANY_OS_STACKER)
                    cfg.set(crate::plugins::windows::mftscan::ANY_OS_STACKER, ConfigValue::Bool(true));
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.timeline_batches(ctx, &cfg)))
                        .unwrap_or_else(|_| Some((Vec::new(), Some(Error::msg("plugin panicked")))))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Some((Vec::new(), Some(Error::msg("plugin panicked")))))).collect()
    })
}

impl Plugin for Timeliner {
    fn name(&self) -> &'static str {
        "timeliner.Timeliner"
    }
    fn description(&self) -> &'static str {
        "Runs all relevant plugins that provide time related information and orders the results by time."
    }
    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::flag("record-config", "Whether to record the state of all the plugins once complete"),
            Requirement::new("plugin-filter", "Only run plugins featuring this substring", ReqKind::ListStr)
                .optional()
                .default(ConfigValue::List(Vec::new())),
            Requirement::flag("create-bodyfile", "Whether to create a body file whilst producing results"),
        ]
    }
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()> {
        let plugins = usable_plugins(&cfg.get_strs("plugin-filter"));
        let results = run_all(ctx, &plugins);
        // python constructs the plugins first: unsatisfied ones never run
        let ran: Vec<(&'static dyn Plugin, Ran)> = plugins
            .iter()
            .zip(results)
            .filter_map(|(p, r)| match r {
                Some((ev, Some(Error::Unsatisfied(_)))) if ev.iter().all(|b| b.is_empty()) => None,
                Some(r) => Some((*p, r)),
                None => None,
            })
            .collect();
        if cfg.get_bool("record-config") {
            record_config(ctx, &ran.iter().map(|(p, _)| *p).collect::<Vec<_>>())?;
        }
        out.begin(vec![
            Column::new("Plugin", ColType::Str),
            Column::new("Description", ColType::Str),
            Column::new("Created Date", ColType::DateTime),
            Column::new("Modified Date", ColType::DateTime),
            Column::new("Accessed Date", ColType::DateTime),
            Column::new("Changed Date", ColType::DateTime),
        ])?;
        let mut body = if cfg.get_bool("create-bodyfile") {
            let (f, _) = ctx.create_output_file("volatility.body")?;
            Some(std::io::BufWriter::with_capacity(1 << 20, f))
        } else {
            None
        };
        let mut m = Merge::default();
        for (p, (events, err)) in ran {
            let class = p.name().rsplit('.').next().unwrap_or("");
            let ci = match m.classes.iter().position(|c| *c == class) {
                Some(i) => i,
                None => {
                    m.classes.push(class);
                    m.classes.len() - 1
                }
            } as u16;
            m.add_events(ci, events);
            if err.is_none() {
                m.pass(&mut body)?;
            }
        }
        if let Some(w) = body.as_mut() {
            w.flush()?;
        }
        let mut rows = m.sorted_rows()?;
        // python's TreeGrid rejects the first row holding a non-datetime time (e.g. the None
        // creation time of linux.pslist when the boot time is unknown): the rows before it
        // are rendered, then the TypeError ends the run
        let rejected = rows.iter().position(|&(_, s)| m.snaps[s as usize].iter().any(|t| matches!(t, Tv::Other(_)))).map(|i| {
            let t = m.snaps[rows[i].1 as usize];
            rows.truncate(i);
            let (k, j) = t.iter().enumerate().find_map(|(k, t)| if let Tv::Other(j) = *t { Some((k, j)) } else { None }).unwrap_or((0, 0));
            const NAMES: [&str; 4] = ["Created Date", "Modified Date", "Accessed Date", "Changed Date"];
            let got = match &m.others[j as usize] {
                Value::None => "NoneType",
                Value::Int(_) => "int",
                Value::Bool(_) => "bool",
                Value::Float(_) => "float",
                Value::Str(_) | Value::SStr(_) => "str",
                Value::Bytes(_) => "bytes",
                _ => "object",
            };
            Error::msg(format!(
                "TypeError: Values item with index {} is the wrong type for column {} (got <class '{got}'> but expected <class 'datetime.datetime'>)",
                k + 2,
                NAMES[k]
            ))
        });
        let values = |&(e, s): &(u32, u32)| {
            let en = &m.entries[e as usize];
            let t = m.snaps[s as usize];
            [Value::SStr(m.classes[en.class as usize]), Value::SStr(en.desc), m.cell(t[0]), m.cell(t[1]), m.cell(t[2]), m.cell(t[3])]
        };
        let Some(enc) = out.encoder() else {
            for r in &rows {
                out.row_ref(0, &values(r))?;
            }
            return rejected.map_or(Ok(()), Err);
        };
        // format blocks of rows on all cores, hand them to the renderer in order; the block
        // buffers are recycled (no fresh pages to fault in for every block)
        const BLOCK: usize = 1 << 14;
        let pool: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
        let mut result = Ok(());
        crate::util::par::par_map_stream(
            rows.len().div_ceil(BLOCK),
            64,
            |b| {
                let part = &rows[b * BLOCK..((b + 1) * BLOCK).min(rows.len())];
                let mut buf = pool.lock().unwrap_or_else(|e| e.into_inner()).pop().unwrap_or_default();
                buf.clear();
                for r in part {
                    enc.row(&mut buf, &values(r));
                }
                (buf, part.len())
            },
            |_, (buf, n)| {
                result = out.rows_encoded_owned(buf, n).map(|back| {
                    if let Some(b) = back {
                        pool.lock().unwrap_or_else(|e| e.into_inner()).push(b);
                    }
                });
                result.is_ok()
            },
        );
        result?;
        rejected.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(secs: i64, micros: u32) -> DateTime {
        DateTime { secs, micros, utc: true }
    }

    #[test]
    fn int_timestamp_like_python() {
        assert_eq!(py_int_timestamp(&dt(1789354424, 0)), 1789354424);
        assert_eq!(py_int_timestamp(&dt(-5, 500_000)), -4);
        assert_eq!(py_int_timestamp(&dt(-11644473600, 0)), -11644473600);
        assert_eq!(py_int_timestamp(&dt(-11644473600, 999_999)), -11644473599);
        // year 9999: 1e-6 is below float resolution -> rounds up like python
        assert_eq!(py_int_timestamp(&dt(253402300799, 999_999)), 253402300800);
        assert_eq!(py_int_timestamp(&dt(253402300799, 999_900)), 253402300799);
    }

    /// `cargo test --release timeliner_scale -- --ignored --nocapture`: the reference image's
    /// shape (16 passes, 311k MFT entries, 2.84M rows) merged, sorted and rendered to a sink.
    #[test]
    #[ignore]
    fn timeliner_scale() {
        let t0 = std::time::Instant::now();
        let mut m = Merge::default();
        let plan: [(&str, usize); 16] = [
            ("PsList", 127),
            ("PsScan", 133),
            ("Amcache", 0),
            ("ThrdScan", 1268),
            ("Threads", 1247),
            ("Threads", 0),
            ("DllList", 0),
            ("MFTScan", 311414),
            ("NetScan", 26),
            ("NetStat", 23),
            ("ScheduledTasks", 348),
            ("Sessions", 111),
            ("ShimcacheMem", 254),
            ("SymlinkScan", 216),
            ("UnloadedModules", 7),
            ("UserAssist", 23),
        ];
        for (pi, (class, n)) in plan.iter().enumerate() {
            m.classes.push(class);
            for i in 0..*n {
                for (ki, k) in [TimeKind::Created, TimeKind::Modified, TimeKind::Accessed].into_iter().enumerate() {
                    let dt = DateTime { secs: 1_700_000_000 + ((i * 7919 + pi) % 100_000) as i64 + ki as i64 * 13, micros: 0, utc: true };
                    m.add_event(pi as u16, TimelineEvent { description: format!("{class} entry {i} some/path/name.ext"), kind: k, time: Value::DateTime(dt) });
                }
            }
            m.pass(&mut None).unwrap();
        }
        let t1 = t0.elapsed();
        let rows = m.sorted_rows().unwrap();
        let t2 = t0.elapsed();
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut r = crate::renderers::text::create("quick", &mut sink, Default::default()).unwrap();
            r.begin(vec![
                Column::new("Plugin", ColType::Str),
                Column::new("Description", ColType::Str),
                Column::new("Created Date", ColType::DateTime),
                Column::new("Modified Date", ColType::DateTime),
                Column::new("Accessed Date", ColType::DateTime),
                Column::new("Changed Date", ColType::DateTime),
            ])
            .unwrap();
            for &(e, s) in &rows {
                let en = &m.entries[e as usize];
                let t = m.snaps[s as usize];
                r.row(0, vec![Value::SStr(m.classes[en.class as usize]), Value::SStr(en.desc), m.cell(t[0]), m.cell(t[1]), m.cell(t[2]), m.cell(t[3])]).unwrap();
            }
            r.finish().unwrap();
        }
        let t3 = t0.elapsed();
        eprintln!("rows {} merge {:?} sort {:?} render {:?} ({} MB)", rows.len(), t1, t2 - t1, t3 - t2, sink.len() >> 20);
    }

    /// The parallel `add_bulk` ends in exactly the state of `add_event` per event: entries,
    /// their values, `cur`, and what the passes snapshot (also with existing entries of the
    /// same class, as with the two `Threads` plugins).
    #[test]
    fn bulk_merge_matches_serial() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let kinds = [TimeKind::Created, TimeKind::Modified, TimeKind::Accessed, TimeKind::Changed];
        for round in 0..8 {
            let pool = [50u64, 5_000, 200_000][round % 3];
            // odd rounds: also non-date values (python can't sort those: rows not compared)
            let others = round % 2 == 1;
            let mut plugins: Vec<(u16, Vec<TimelineBatch>)> = Vec::new();
            for p in 0..4 {
                let class = [0u16, 1, 0, 2][p];
                let nb = 1 + rnd(12) as usize;
                let batches: Vec<TimelineBatch> = (0..nb)
                    .map(|_| {
                        let date = |r: &mut dyn FnMut(u64) -> u64| dt(1_600_000_000 + r(1_000_000) as i64, r(3) as u32);
                        if rnd(2) == 0 {
                            // compact groups (MFTScan): random type order, some unset (all unset too)
                            let mut order = kinds;
                            order.swap(rnd(4) as usize, rnd(4) as usize);
                            let mut g = crate::plugins::TimelineGroups::new(order);
                            for _ in 0..rnd(1500) {
                                let d = format!("entry {}", rnd(pool));
                                let t = [0; 4].map(|_| match rnd(8) {
                                    0 => TimelineTime::Unset,
                                    1 => TimelineTime::NotApplicable,
                                    2 => TimelineTime::Unparsable,
                                    _ => TimelineTime::DateTime(date(&mut rnd)),
                                });
                                g.push(&d, t);
                            }
                            return TimelineBatch::Groups(g);
                        }
                        let mut v = Vec::new();
                        for _ in 0..rnd(1500) {
                            // an entry's events back to back (like MFT records), 1-5 of them
                            let description = format!("entry {}", rnd(pool));
                            for _ in 0..1 + rnd(5) {
                                let time = match rnd(10) {
                                    0 => Value::NotApplicable,
                                    1 => Value::Unreadable,
                                    2 => Value::NotAvailable,
                                    3 if others => Value::Int(rnd(1000) as i128),
                                    _ => Value::DateTime(date(&mut rnd)),
                                };
                                v.push(TimelineEvent { description: description.clone(), kind: kinds[rnd(4) as usize], time });
                            }
                        }
                        TimelineBatch::Events(v)
                    })
                    .collect();
                plugins.push((class, batches));
            }
            let run = |bulk: bool| {
                let mut m = Merge { classes: vec!["A", "B", "C"], ..Default::default() };
                for (class, batches) in plugins.iter() {
                    let b = batches.clone();
                    if bulk {
                        m.add_bulk(*class, b);
                    } else {
                        m.refresh_index(*class);
                        for ev in b.into_iter().flat_map(TimelineBatch::into_events) {
                            m.add_event(*class, ev);
                        }
                    }
                    m.pass(&mut None).unwrap();
                }
                let show = |t: Tv| match t {
                    Tv::Other(i) => format!("{:?}", m.others[i as usize]),
                    t => format!("{t:?}"),
                };
                let entries: Vec<String> =
                    m.entries.iter().map(|e| format!("{} {} {:?}", e.class, e.desc, e.times.map(show))).collect();
                let snaps: Vec<String> = m.rows.iter().map(|&(e, s)| format!("{e} {:?}", m.snaps[s as usize].map(show))).collect();
                let rows: Vec<String> = if others {
                    Vec::new()
                } else {
                    m.sorted_rows().unwrap().iter().map(|&(e, s)| format!("{e} {:?}", m.snaps[s as usize].map(show))).collect()
                };
                (entries, m.cur, snaps, rows)
            };
            let (a, b) = (run(false), run(true));
            assert_eq!(a.0.len(), b.0.len(), "round {round}");
            assert!(a == b, "round {round}");
        }
    }

    /// python's sort raises exactly when two keys first differ at elements it cannot order
    /// (None / naive datetimes vs aware ones); otherwise it sorts, and the renderer stops at
    /// the first row holding a None.
    #[test]
    fn sort_type_errors_like_python() {
        let ev = |d: &str, k, t| TimelineEvent { description: d.into(), kind: k, time: t };
        let run = |events: Vec<Vec<TimelineEvent>>| {
            let mut m = Merge { classes: vec!["A", "B", "C"], ..Default::default() };
            for (c, evs) in events.into_iter().enumerate() {
                for e in evs {
                    m.add_event(c as u16, e);
                }
                m.pass(&mut None).unwrap();
            }
            let r = m.sorted_rows().map(|rows| rows.iter().map(|&(e, s)| (e, m.snaps[s as usize])).collect::<Vec<_>>());
            (r, m)
        };
        let naive = |secs| Value::DateTime(DateTime { secs, micros: 0, utc: false });
        // a None created time (linux.pslist without boot time), then datetimes: TypeError
        let (r, _) = run(vec![vec![ev("p", TimeKind::Created, Value::None)], vec![ev("x", TimeKind::Created, Value::DateTime(dt(5, 0)))]]);
        assert_eq!(r.unwrap_err().to_string(), "TypeError: '<' not supported between instances of 'datetime.datetime' and 'NoneType'");
        // None only: python sorts (equal keys); the rows keep their order
        let (r, _) = run(vec![vec![ev("p", TimeKind::Created, Value::None), ev("q", TimeKind::Created, Value::None)]]);
        assert_eq!(r.unwrap().iter().map(|x| x.0).collect::<Vec<_>>(), vec![0, 1]);
        // None equal in the first element, the keys differ later at datetimes: sortable
        let (r, _) = run(vec![
            vec![ev("p", TimeKind::Created, Value::None), ev("p", TimeKind::Modified, Value::DateTime(dt(9, 0)))],
            vec![ev("q", TimeKind::Created, Value::None), ev("q", TimeKind::Modified, Value::DateTime(dt(3, 0)))],
        ]);
        let rows = r.unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].1[1], Tv::Dt(dt(3, 0)));
        // naive datetimes sort among themselves, but not against absent values (aware max_date)
        let (r, _) = run(vec![vec![ev("a", TimeKind::Created, naive(7)), ev("b", TimeKind::Created, naive(2))]]);
        assert!(r.is_ok());
        let (r, _) = run(vec![vec![ev("a", TimeKind::Created, naive(7))], vec![ev("b", TimeKind::Modified, Value::DateTime(dt(1, 0)))]]);
        assert_eq!(r.unwrap_err().to_string(), "TypeError: can't compare offset-naive and offset-aware datetimes");
    }

    #[test]
    fn merge_quirks() {
        let mut m = Merge { classes: vec!["A", "B"], ..Default::default() };
        let ev = |d: &str, k, t| TimelineEvent { description: d.into(), kind: k, time: t };
        m.add_event(0, ev("x", TimeKind::Created, Value::DateTime(dt(10, 0))));
        m.add_event(0, ev("y", TimeKind::Created, Value::DateTime(dt(5, 0))));
        m.pass(&mut None).unwrap();
        m.add_event(1, ev("z", TimeKind::Modified, Value::DateTime(dt(1, 0))));
        m.pass(&mut None).unwrap();
        // pass 1: x,y with y's times; pass 2: x,y,z with z's times
        let rows = m.sorted_rows().unwrap();
        let got: Vec<(u32, [Tv; 4])> = rows.iter().map(|&(e, s)| (e, m.snaps[s as usize])).collect();
        assert_eq!(got.len(), 5);
        assert_eq!(got[0].0, 0);
        assert_eq!(got[0].1[0], Tv::Dt(dt(5, 0)));
        assert_eq!(got[1].0, 1);
        assert_eq!(got[2].0, 0);
        assert_eq!(got[2].1[1], Tv::Dt(dt(1, 0)));
        assert_eq!(got[4].0, 2);
    }
}
