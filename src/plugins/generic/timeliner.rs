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
use crate::plugins::{Config, ConfigValue, Plugin, ReqKind, Requirement, TimeKind, TimelineEvent};
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
struct Merge {
    classes: Vec<&'static str>,
    entries: Vec<Entry>,
    index: FxHashMap<(u16, &'static str), u32>,
    snaps: Vec<[Tv; 4]>,
    others: Vec<Value>,
    /// python's loop variable `times` (an entry)
    cur: Option<u32>,
    rows: Vec<(u32, u32)>,
}

impl Merge {
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
        let k = (class, ev.description.as_str());
        let idx = match self.index.get(&k) {
            Some(&i) => i,
            None => {
                let desc: &'static str = Box::leak(ev.description.into_boxed_str());
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

    /// python `sorted(data, key=self._sort_function)`: row order.
    fn sorted_rows(&self) -> Vec<(u32, u32)> {
        // sort key of one cell; naive datetimes / other values can't be compared with the
        // aware max_date by python (TypeError)
        let key = |t: Tv| -> (i64, u32) {
            match t {
                Tv::Dt(dt) => {
                    if !dt.utc {
                        panic!("TypeError: can't compare offset-naive and offset-aware datetimes");
                    }
                    (dt.secs, dt.micros)
                }
                Tv::Other(_) => panic!("TypeError: '<' not supported between instances"),
                _ => (MAX_DATE_SECS, 0),
            }
        };
        if self.rows.len() < 2 {
            return self.rows.clone();
        }
        let keys: Vec<[(i64, u32); 4]> = self.snaps.iter().map(|s| [key(s[0]), key(s[1]), key(s[2]), key(s[3])]).collect();
        let mut order: Vec<u32> = (0..keys.len() as u32).collect();
        order.sort_unstable_by(|&a, &b| keys[a as usize].cmp(&keys[b as usize]));
        let mut rank = vec![0u32; keys.len()];
        let mut r = 0u32;
        for (i, &s) in order.iter().enumerate() {
            if i > 0 && keys[s as usize] != keys[order[i - 1] as usize] {
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
        out
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

/// The python requirements of the timeliner plugins as far as `build_configuration()` records
/// them: `K` = ModuleRequirement("kernel"), `P` = TranslationLayerRequirement("primary"),
/// `v:` VersionRequirement (recorded as `false`), `b:` BooleanRequirement (its value),
/// `l:` optional ListRequirement without default (recorded as `[]`). Int/String requirements
/// without a default are not recorded.
const TIMELINER_REQS: [(&str, &[&str]); 22] = [
    ("windows.pslist.PsList", &["K", "b:physical", "v:timeliner", "l:pid", "b:dump"]),
    ("windows.psscan.PsScan", &["K", "v:pslist", "v:timeliner", "v:info", "v:poolscanner", "l:pid", "b:dump", "b:physical"]),
    ("linux.pslist.PsList", &["K", "v:elfs", "l:pid", "v:timeliner", "b:threads", "b:decorate_comm", "b:dump"]),
    ("linux.bash.Bash", &["K", "v:pslist", "v:timeliner", "v:multi_string_scanner", "v:bytes_scanner", "l:pid"]),
    ("linux.boottime.Boottime", &["K", "v:timeliner", "v:pslist"]),
    ("linux.lsof.Lsof", &["K", "v:pslist", "v:timeliner", "v:linuxutils", "l:pid", "b:files_only"]),
    ("linux.pagecache.Files", &["K", "v:mountinfo", "v:timeliner", "l:type"]),
    ("mac.bash.Bash", &["K", "v:pslist", "v:timeliner", "v:multi_string_scanner", "v:bytes_scanner", "l:pid"]),
    ("windows.registry.amcache.Amcache", &["K", "v:hivelist", "v:timeliner"]),
    ("windows.thrdscan.ThrdScan", &["K", "v:poolscanner", "v:pe_symbols", "v:timeliner"]),
    ("windows.threads.Threads", &["K", "v:thrdscan", "v:pslist"]),
    ("windows.orphan_kernel_threads.Threads", &["K", "v:thrdscan", "v:ssdt", "v:modules"]),
    ("windows.dlllist.DllList", &["K", "v:pslist", "v:timeliner", "v:psscan", "v:pedump", "v:info", "l:pid", "b:ignore-case", "b:dump"]),
    ("windows.mftscan.MFTScan", &["P", "v:timeliner", "v:yarascanner", "v:yarascan"]),
    ("windows.netscan.NetScan", &["K", "v:poolscanner", "v:info", "v:timeliner", "v:verinfo", "b:include-corrupt"]),
    ("windows.netstat.NetStat", &["K", "v:netscan", "v:modules", "v:timeliner", "v:pdbutil", "v:info", "v:verinfo", "b:include-corrupt"]),
    ("windows.registry.scheduled_tasks.ScheduledTasks", &["K", "v:hivelist", "v:timeliner"]),
    ("windows.sessions.Sessions", &["K", "v:pslist", "v:timeliner", "l:pid"]),
    ("windows.shimcachemem.ShimcacheMem", &["K", "v:pslist", "v:timeliner", "v:vadinfo", "v:modules"]),
    ("windows.symlinkscan.SymlinkScan", &["K", "v:timeliner", "v:poolscanner"]),
    ("windows.unloadedmodules.UnloadedModules", &["K", "v:timeliner", "v:modules"]),
    ("windows.registry.userassist.UserAssist", &["K", "v:hivelist", "v:timeliner"]),
];

/// `--record-config`: python writes `config.json` (`json.dump(total_config, sort_keys=True,
/// indent=2)`) with every constructed plugin's `build_configuration()` under `<Class>.`.
fn record_config(ctx: &Context, plugins: &[&'static dyn Plugin]) -> Result<()> {
    use crate::cli::json::Json;
    let mut items: super::pyconfig::Items = Vec::new();
    for p in plugins {
        let class = p.name().rsplit('.').next().unwrap_or("");
        let cfg = crate::plugins::default_config(*p);
        let reqs = TIMELINER_REQS.iter().find(|(n, _)| *n == p.name()).map(|(_, r)| *r).unwrap_or(&[]);
        for r in reqs {
            match *r {
                "K" => items.extend(super::pyconfig::kernel_tree(ctx, p.name(), &format!("{class}.kernel"))?),
                "P" => {
                    let prim = super::primary::primary(ctx, "Memory layer for the kernel")?;
                    items.extend(super::pyconfig::primary_tree(ctx, &prim, &format!("{class}.primary"), false, true)?);
                }
                r => {
                    let (kind, name) = r.split_once(':').unwrap_or(("", r));
                    let v = match kind {
                        "v" => Json::Bool(false),
                        "b" => Json::Bool(cfg.get_bool(name)),
                        _ => Json::Arr(cfg.get_strs(name).into_iter().map(Json::Str).collect()),
                    };
                    items.push((format!("{class}.{name}"), v));
                }
            }
        }
    }
    let (mut f, _) = ctx.create_output_file("config.json")?;
    f.write_all(Json::Obj(items).dump(Some(2)).as_bytes())?;
    Ok(())
}

type Outcome = Option<(Vec<TimelineEvent>, Option<Error>)>;

/// Run the plugins' timelines concurrently; a panicking plugin is python's `except Exception`.
fn run_all(ctx: &Context, plugins: &[&'static dyn Plugin]) -> Vec<Outcome> {
    std::thread::scope(|s| {
        let handles: Vec<_> = plugins
            .iter()
            .map(|p| {
                let p = *p;
                s.spawn(move || {
                    let cfg = crate::plugins::default_config(p);
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.timeline_events(ctx, &cfg)))
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
        let ran: Vec<(&'static dyn Plugin, (Vec<TimelineEvent>, Option<Error>))> = plugins
            .iter()
            .zip(results)
            .filter_map(|(p, r)| match r {
                Some((ev, Some(Error::Unsatisfied(_)))) if ev.is_empty() => None,
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
        let mut m = Merge {
            classes: Vec::new(),
            entries: Vec::new(),
            index: FxHashMap::default(),
            snaps: Vec::new(),
            others: Vec::new(),
            cur: None,
            rows: Vec::new(),
        };
        for (p, (events, err)) in ran {
            let class = p.name().rsplit('.').next().unwrap_or("");
            let ci = match m.classes.iter().position(|c| *c == class) {
                Some(i) => i,
                None => {
                    m.classes.push(class);
                    m.classes.len() - 1
                }
            } as u16;
            for ev in events {
                m.add_event(ci, ev);
            }
            if err.is_none() {
                m.pass(&mut body)?;
            }
        }
        if let Some(w) = body.as_mut() {
            w.flush()?;
        }
        for (e, s) in m.sorted_rows() {
            let en = &m.entries[e as usize];
            let t = m.snaps[s as usize];
            out.row(
                0,
                vec![
                    Value::SStr(m.classes[en.class as usize]),
                    Value::SStr(en.desc),
                    m.cell(t[0]),
                    m.cell(t[1]),
                    m.cell(t[2]),
                    m.cell(t[3]),
                ],
            )?;
        }
        Ok(())
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
        let mut m = Merge { classes: Vec::new(), entries: Vec::new(), index: FxHashMap::default(), snaps: Vec::new(), others: Vec::new(), cur: None, rows: Vec::new() };
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
                for k in [TimeKind::Created, TimeKind::Modified, TimeKind::Accessed] {
                    let dt = DateTime { secs: 1_700_000_000 + ((i * 7919 + pi) % 100_000) as i64, micros: 0, utc: true };
                    m.add_event(pi as u16, TimelineEvent { description: format!("{class} entry {i} some/path/name.ext"), kind: k, time: Value::DateTime(dt) });
                }
            }
            m.pass(&mut None).unwrap();
        }
        let t1 = t0.elapsed();
        let rows = m.sorted_rows();
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

    #[test]
    fn merge_quirks() {
        let mut m = Merge { classes: vec!["A", "B"], entries: Vec::new(), index: FxHashMap::default(), snaps: Vec::new(), others: Vec::new(), cur: None, rows: Vec::new() };
        let ev = |d: &str, k, t| TimelineEvent { description: d.into(), kind: k, time: t };
        m.add_event(0, ev("x", TimeKind::Created, Value::DateTime(dt(10, 0))));
        m.add_event(0, ev("y", TimeKind::Created, Value::DateTime(dt(5, 0))));
        m.pass(&mut None).unwrap();
        m.add_event(1, ev("z", TimeKind::Modified, Value::DateTime(dt(1, 0))));
        m.pass(&mut None).unwrap();
        // pass 1: x,y with y's times; pass 2: x,y,z with z's times
        let rows = m.sorted_rows();
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
