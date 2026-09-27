//! Plugin interface, requirement declarations (drive CLI parsing + `--help`), per-run
//! configuration values, and the plugin registry.
//!
//! CONTRACT (stable):
//!   * Every plugin is a unit struct implementing [`Plugin`], registered in its group's
//!     `register()` (windows/linux/mac/generic `mod.rs`).
//!   * `requirements()` lists ONLY the user-visible (CLI) options, in the same order as the
//!     python plugin's `get_requirements()` so `--help` output matches argparse.
//!     Hidden/complex python requirements (kernel ModuleRequirement, TranslationLayer,
//!     SymbolTable, PluginRequirement, VersionRequirement) are NOT listed; plugins obtain
//!     kernel/layers/symbols lazily from the `Context`. (python's complete lists, which saved
//!     configurations need, are data generated from python: [`pyreqs`].)
//!   * `run()` writes columns then rows into the sink (see `renderers` contract).

pub mod generic;
pub mod linux;
pub mod mac;
pub mod pyreqs;
pub mod windows;

use crate::context::Context;
use crate::error::Result;
use crate::renderers::{RowBlock, RowSink, Value};

/// Kind of a CLI-visible requirement (mirrors volatility3's SimpleTypeRequirement subclasses,
/// ListRequirement and ChoiceRequirement).
#[derive(Clone, Debug, PartialEq)]
pub enum ReqKind {
    /// BooleanRequirement -> `--flag` (store_true)
    Bool,
    /// IntRequirement -> `--name NAME` parsed with python `int(x, 0)` semantics
    Int,
    /// StringRequirement
    Str,
    /// BytesRequirement
    Bytes,
    /// URIRequirement
    Uri,
    /// ListRequirement(element_type=int) -> `--name [NAME ...]` (nargs `*` if optional else `+`)
    ListInt,
    /// ListRequirement(element_type=str)
    ListStr,
    /// ChoiceRequirement(choices)
    Choice(Vec<&'static str>),
}

/// A configuration value.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigValue {
    Bool(bool),
    Int(i128),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<ConfigValue>),
}

/// A user-visible plugin option.
#[derive(Clone, Debug)]
pub struct Requirement {
    /// python requirement name, e.g. "pid", "dump", "physical", "include-corrupt" style names
    /// keep their python spelling (underscores); the CLI maps `_` -> `-` for the flag.
    pub name: &'static str,
    pub description: &'static str,
    pub kind: ReqKind,
    pub default: Option<ConfigValue>,
    pub optional: bool,
}

impl Requirement {
    pub fn new(name: &'static str, description: &'static str, kind: ReqKind) -> Requirement {
        Requirement { name, description, kind, default: None, optional: false }
    }
    /// BooleanRequirement(name, description, default=False, optional=True) - the common case.
    pub fn flag(name: &'static str, description: &'static str) -> Requirement {
        Requirement { name, description, kind: ReqKind::Bool, default: Some(ConfigValue::Bool(false)), optional: true }
    }
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    pub fn default(mut self, v: ConfigValue) -> Self {
        self.default = Some(v);
        self
    }
}

/// Values for one plugin run (CLI options after parsing, defaults applied). (FxHash: std's
/// randomly seeded SipHash costs a `getrandom` system call per process for nothing; every user
/// of the map sorts or looks up, none depends on its order.)
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub values: crate::util::FxHashMap<String, ConfigValue>,
}

impl Config {
    pub fn get(&self, name: &str) -> Option<&ConfigValue> {
        self.values.get(name)
    }
    pub fn set(&mut self, name: &str, v: ConfigValue) {
        self.values.insert(name.to_string(), v);
    }
    /// false when missing
    pub fn get_bool(&self, name: &str) -> bool {
        matches!(self.values.get(name), Some(ConfigValue::Bool(true)))
    }
    pub fn get_int(&self, name: &str) -> Option<i128> {
        match self.values.get(name) {
            Some(ConfigValue::Int(i)) => Some(*i),
            _ => None,
        }
    }
    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.values.get(name) {
            Some(ConfigValue::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }
    pub fn get_bytes(&self, name: &str) -> Option<&[u8]> {
        match self.values.get(name) {
            Some(ConfigValue::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    }
    /// List of ints (empty when missing / None).
    pub fn get_ints(&self, name: &str) -> Vec<i128> {
        match self.values.get(name) {
            Some(ConfigValue::List(l)) => l
                .iter()
                .filter_map(|v| if let ConfigValue::Int(i) = v { Some(*i) } else { None })
                .collect(),
            _ => Vec::new(),
        }
    }
    /// List of strings (empty when missing / None).
    pub fn get_strs(&self, name: &str) -> Vec<String> {
        match self.values.get(name) {
            Some(ConfigValue::List(l)) => l
                .iter()
                .filter_map(|v| if let ConfigValue::Str(s) = v { Some(s.clone()) } else { None })
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// Timeline event kinds (volatility3 `timeliner.TimeLinerType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeKind {
    Created,
    Modified,
    Accessed,
    Changed,
}

/// One timeline event (volatility3 `generate_timeline` yields `(description, type, datetime)`).
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    pub description: String,
    pub kind: TimeKind,
    /// `Value::DateTime` or an absent value.
    pub time: Value,
}

/// A timeline time in compact form: a datetime or one of python's absent values.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TimelineTime {
    /// no event of this type in the group
    Unset,
    DateTime(crate::renderers::DateTime),
    NotApplicable,
    Unreadable,
    Unparsable,
    NotAvailable,
}

impl TimelineTime {
    /// The compact form of a timeline `Value` (None for values it can't hold).
    pub fn from_value(v: &Value) -> Option<TimelineTime> {
        Some(match v {
            Value::DateTime(dt) => TimelineTime::DateTime(*dt),
            Value::NotApplicable => TimelineTime::NotApplicable,
            Value::Unreadable => TimelineTime::Unreadable,
            Value::Unparsable => TimelineTime::Unparsable,
            Value::NotAvailable => TimelineTime::NotAvailable,
            _ => return None,
        })
    }
    /// The `Value` (None for `Unset`).
    pub fn value(self) -> Option<Value> {
        Some(match self {
            TimelineTime::Unset => return None,
            TimelineTime::DateTime(dt) => Value::DateTime(dt),
            TimelineTime::NotApplicable => Value::NotApplicable,
            TimelineTime::Unreadable => Value::Unreadable,
            TimelineTime::Unparsable => Value::Unparsable,
            TimelineTime::NotAvailable => Value::NotAvailable,
        })
    }
}

/// Timeline events in compact form, for plugins yielding millions (MFT scans): groups of
/// consecutive events with the same description. A group stands for its events in the order
/// `order` (python's yield order), one per set time; the descriptions are back to back in
/// `text`.
#[derive(Clone, Debug)]
pub struct TimelineGroups {
    pub text: String,
    /// per group: end of its description in `text`, time per type (indexed like `order`)
    pub groups: Vec<(u32, [TimelineTime; 4])>,
    /// the types of a group's events in yield order
    pub order: [TimeKind; 4],
}

impl TimelineGroups {
    pub fn new(order: [TimeKind; 4]) -> TimelineGroups {
        TimelineGroups { text: String::new(), groups: Vec::new(), order }
    }
    /// Append a group.
    pub fn push(&mut self, desc: &str, times: [TimelineTime; 4]) {
        self.text.push_str(desc);
        self.groups.push((self.text.len() as u32, times));
    }
    /// The description of group `i`.
    pub fn desc(&self, i: usize) -> &str {
        let start = if i == 0 { 0 } else { self.groups[i - 1].0 as usize };
        &self.text[start..self.groups[i].0 as usize]
    }
    /// The events, one by one.
    pub fn events(&self) -> impl Iterator<Item = TimelineEvent> + '_ {
        (0..self.groups.len()).flat_map(move |i| {
            let d = self.desc(i);
            (0..4).filter_map(move |k| {
                self.groups[i].1[k].value().map(|time| TimelineEvent { description: d.to_string(), kind: self.order[k], time })
            })
        })
    }
}

/// A run of a plugin's timeline events: plain, or compact groups.
#[derive(Clone, Debug)]
pub enum TimelineBatch {
    Events(Vec<TimelineEvent>),
    Groups(TimelineGroups),
}

impl TimelineBatch {
    /// Number of events.
    pub fn len(&self) -> usize {
        match self {
            TimelineBatch::Events(v) => v.len(),
            TimelineBatch::Groups(g) => g.groups.iter().map(|x| x.1.iter().filter(|t| **t != TimelineTime::Unset).count()).sum(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The events, one by one.
    pub fn into_events(self) -> Vec<TimelineEvent> {
        match self {
            TimelineBatch::Events(v) => v,
            TimelineBatch::Groups(g) => g.events().collect(),
        }
    }
}

/// A volatility plugin.
pub trait Plugin: Sync {
    /// Full dotted name as volatility3 prints it, e.g. "windows.pslist.PsList".
    fn name(&self) -> &'static str;
    /// Text shown in the `fvol -h` plugin list (python class docstring, first paragraph).
    /// Empty when the python class has no docstring.
    fn description(&self) -> &'static str;
    /// The rest of the python docstring after the first blank line (argparse epilog of
    /// `fvol <plugin> -h`), if any.
    fn epilog(&self) -> Option<&'static str> {
        None
    }
    /// CLI-visible requirements in python order.
    fn requirements(&self) -> Vec<Requirement> {
        Vec::new()
    }
    /// Produce the output.
    fn run(&self, ctx: &Context, cfg: &Config, out: &mut dyn RowSink) -> Result<()>;
    /// Timeliner support (python `TimeLinerInterface.generate_timeline`). `None` = not supported.
    fn timeline(&self, _ctx: &Context, _cfg: &Config) -> Option<Result<Vec<TimelineEvent>>> {
        None
    }
    /// python's `generate_timeline` generator including the case where it raises midway: the
    /// events yielded before the exception plus the error (the timeliner keeps those events).
    /// Override this instead of [`Plugin::timeline`] when the python generator can raise after
    /// its first yield; the default wraps `timeline()` (an `Err` there yields no events).
    /// `Some((vec![], Some(Error::Unsatisfied(..))))` = python could not construct the plugin.
    fn timeline_events(&self, ctx: &Context, cfg: &Config) -> Option<(Vec<TimelineEvent>, Option<crate::error::Error>)> {
        self.timeline(ctx, cfg).map(|r| match r {
            Ok(v) => (v, None),
            Err(e) => (Vec::new(), Some(e)),
        })
    }
    /// [`Plugin::timeline_events`] as consecutive batches (the events in order are the batches
    /// concatenated), so producers of millions of events (MFT scans) hand over their per-worker
    /// results, in compact form, without concatenating them. Default: `timeline_events` as one
    /// batch.
    #[allow(clippy::type_complexity)]
    fn timeline_batches(&self, ctx: &Context, cfg: &Config) -> Option<(Vec<TimelineBatch>, Option<crate::error::Error>)> {
        self.timeline_events(ctx, cfg).map(|(v, e)| (vec![TimelineBatch::Events(v)], e))
    }
}

/// The plugin's configuration with every requirement default applied (what python's
/// automagic/CLI gives a plugin constructed without options, e.g. by the timeliner).
pub fn default_config(p: &dyn Plugin) -> Config {
    let mut cfg = Config::default();
    for r in p.requirements() {
        if let Some(d) = r.default {
            cfg.set(r.name, d);
        }
    }
    cfg
}

/// The error python reports as an `UnsatisfiedException` (printed by the CLI as
/// "Unsatisfied requirement plugins.<Class>.<path>: ..." + hints, exit status 1).
/// `paths` are config paths relative to the plugin, e.g. `["kernel.layer_name",
/// "kernel.symbol_table_name"]` (what the CLI assumes when an `Error::Unsatisfied` message is
/// free text); a path ending in `layer_name` counts as a TranslationLayerRequirement, one ending
/// in `symbol_table_name` as a SymbolTableRequirement.
pub fn unsatisfied(paths: &[&str]) -> crate::error::Error {
    crate::error::Error::Unsatisfied(paths.join("\n"))
}

/// Kind of an unsatisfied requirement (selects the CLI's hint paragraph).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsatKind {
    /// `TranslationLayerRequirement`
    Layer,
    /// `SymbolTableRequirement`
    Symbols,
    /// anything else
    Other,
}

/// [`unsatisfied`] for requirements python prints with a description, e.g. a plugin's own
/// `TranslationLayerRequirement(name="primary", description="Memory layer for the kernel")`:
/// "Unsatisfied requirement plugins.<Class>.primary: Memory layer for the kernel".
pub fn unsatisfied_described(reqs: &[(&str, UnsatKind, &str)]) -> crate::error::Error {
    let lines: Vec<String> = reqs
        .iter()
        .map(|(path, kind, desc)| {
            let k = match kind {
                UnsatKind::Layer => "layer",
                UnsatKind::Symbols => "symbols",
                UnsatKind::Other => "other",
            };
            format!("{path}\t{k}\t{desc}")
        })
        .collect();
    crate::error::Error::Unsatisfied(lines.join("\n"))
}

/// Every registered plugin, in registration order (not sorted, see [`all`]).
pub fn registered() -> Vec<&'static dyn Plugin> {
    let mut v: Vec<&'static dyn Plugin> = Vec::with_capacity(256);
    generic::register(&mut v);
    windows::register(&mut v);
    linux::register(&mut v);
    mac::register(&mut v);
    v
}

/// Every registered plugin, sorted by name.
pub fn all() -> Vec<&'static dyn Plugin> {
    let mut v = registered();
    // Sorted by name (help, the web UI and the timeliner pay for this; a CLI run does not, see
    // `cli::main`). Compare cached keys: the first 16 name bytes
    // as a big-endian integer (orders like the bytes), the full name only on a tie. ~4x fewer
    // instructions than comparing the (long, shared-prefix) names through `name()` calls.
    let prefix = |s: &str| -> u128 {
        let mut b = [0u8; 16];
        let n = s.len().min(16);
        b[..n].copy_from_slice(&s.as_bytes()[..n]);
        u128::from_be_bytes(b)
    };
    v.sort_by_cached_key(|p| (prefix(p.name()), p.name()));
    v
}

/// Look up a plugin by its full name.
pub fn find(name: &str) -> Option<&'static dyn Plugin> {
    all().into_iter().find(|p| p.name() == name)
}

/// `f(i, block)` for every `i in 0..n` in parallel, each pushing its rows into its own
/// [`RowBlock`] (formatted on the worker when the sink has a row encoder); the blocks come back
/// in index order with `f`'s results, for the caller to [`RowBlock::emit`] in python's order.
/// Every block is alive at the end: for outputs that can be large use [`stream_blocks`].
pub fn par_blocks<'e, X: Send>(enc: Option<&'e crate::renderers::text::RowEncoder>, n: usize, f: impl Fn(usize, &mut RowBlock<'e>) -> X + Sync) -> Vec<(RowBlock<'e>, X)> {
    crate::util::par::par_map(n, |i| {
        let mut b = RowBlock::new(enc);
        let x = f(i, &mut b);
        (b, x)
    })
}

/// Items computed per window by [`stream_blocks`] (bounds the output held in memory).
fn stream_window() -> usize {
    8 * crate::util::par::threads().max(2)
}

/// [`par_blocks`] with bounded memory: the items are computed in windows of a few per core and
/// `consume(i, block, x)` gets each on the calling thread in index order before the next
/// window starts. `consume` returning `Ok(false)` or an error stops (later windows are not
/// computed); `consume` may panic (python crashes raised on the output thread).
///
/// A panicking `f` (python's uncaught exceptions are panics) is caught on its worker: `consume`
/// gets that item's rows with `None` (it emits them like any block, python printed the rows
/// before the crash), then the panic is resumed with its own payload. Without this the
/// worker's join would replace the payload ("worker panicked").
pub fn stream_blocks<'e, X: Send>(
    enc: Option<&'e crate::renderers::text::RowEncoder>,
    n: usize,
    f: impl Fn(usize, &mut RowBlock<'e>) -> X + Sync,
    mut consume: impl FnMut(usize, RowBlock<'e>, Option<X>) -> Result<bool>,
) -> Result<()> {
    let w = stream_window();
    let mut start = 0;
    while start < n {
        let end = (start + w).min(n);
        let blocks = par_blocks(enc, end - start, |j, b| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(start + j, b))));
        for (j, (b, x)) in blocks.into_iter().enumerate() {
            match x {
                Ok(x) => {
                    if !consume(start + j, b, Some(x))? {
                        return Ok(());
                    }
                }
                Err(panic) => {
                    consume(start + j, b, None)?;
                    std::panic::resume_unwind(panic);
                }
            }
        }
        start = end;
    }
    Ok(())
}

/// python `for item in items: yield from rows(item)` over `n` items, the rows built and
/// formatted on all cores (see [`RowBlock`]) and handed to `out` in order: `f(range, block)`
/// pushes the rows of the items in `range` (chunks of `chunk` items) and returns python's
/// exception after them, if any; nothing after it is emitted. At most a few chunks per core
/// are computed ahead of the output, so memory stays bounded whatever the output size; a
/// panicking `f` is resumed here after the rows before it (see [`stream_blocks`]).
pub fn stream_chunks(out: &mut dyn RowSink, n: usize, chunk: usize, f: impl Fn(std::ops::Range<usize>, &mut RowBlock) -> Option<crate::error::Error> + Sync) -> Result<()> {
    let chunk = chunk.max(1);
    let enc = out.encoder();
    let enc = enc.as_ref();
    let mut res = Ok(());
    let mut panicked = None;
    crate::util::par::par_map_stream(
        n.div_ceil(chunk),
        4 * crate::util::par::threads(),
        // a panic is caught on the worker and resumed here, in order, like the serial loop
        // would have raised it (an uncaught worker panic would leave the stream waiting
        // forever); the consumer itself never panics (it would, too)
        |c| {
            let mut b = RowBlock::new(enc);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(c * chunk..((c + 1) * chunk).min(n), &mut b)));
            (b, r)
        },
        |_, (b, r)| {
            // the rows before the error / panic first
            res = b.emit(out);
            match r {
                _ if res.is_err() => false,
                Ok(err) => {
                    res = err.map_or(Ok(()), Err);
                    res.is_ok()
                }
                Err(p) => {
                    panicked = Some(p);
                    false
                }
            }
        },
    );
    if let Some(p) = panicked {
        std::panic::resume_unwind(p);
    }
    res
}

/// python `for item in items: yield from rows(item)` with the items' rows computed (and
/// formatted, see [`RowBlock`]) in parallel and emitted in order, with bounded memory (see
/// [`stream_blocks`]). An `Err` item = python raised there (before its rows); `f` returning
/// `Err` = python raised after the rows it pushed.
pub fn emit_par_blocks<T: Sync>(out: &mut dyn RowSink, items: Vec<Result<T>>, f: impl Fn(&T, &mut RowBlock) -> Result<()> + Sync) -> Result<()> {
    let enc = out.encoder();
    let (oks, mut errs): (Vec<Option<T>>, Vec<Option<crate::error::Error>>) = items
        .into_iter()
        .map(|r| match r {
            Ok(t) => (Some(t), None),
            Err(e) => (None, Some(e)),
        })
        .unzip();
    stream_blocks(
        enc.as_ref(),
        oks.len(),
        |i, b| match &oks[i] {
            Some(t) => f(t, b).err(),
            None => None,
        },
        |i, b, err| {
            if let Some(e) = errs[i].take() {
                return Err(e);
            }
            b.emit(out)?;
            match err.flatten() {
                Some(e) => Err(e),
                None => Ok(true),
            }
        },
    )
}

/// [`emit_par_blocks`] for a per-item row function returning python's rows in order (a
/// trailing `Err` = python raised there).
pub fn emit_par_rows<T: Sync>(out: &mut dyn RowSink, items: Vec<Result<T>>, f: impl Fn(&T) -> Vec<Result<Vec<Value>>> + Sync) -> Result<()> {
    emit_par_blocks(out, items, |t, b| {
        for r in f(t) {
            b.push(r?);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::renderers::CollectSink;
    use crate::renderers::text::{RenderOptions, create};

    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Fail {
        None,
        ErrItem(usize),
        ErrAfterRow(usize),
        Panic(usize),
    }

    fn row(i: usize) -> Vec<Value> {
        vec![Value::Int(i as i128), Value::Str(format!("item {i}"))]
    }

    /// Item `i`'s rows: two, with `fail` striking after the first.
    fn body(fail: Fail, i: usize, push: &mut dyn FnMut(Vec<Value>)) -> Result<()> {
        push(row(i));
        if fail == Fail::ErrAfterRow(i) {
            return Err(Error::msg("after"));
        }
        if fail == Fail::Panic(i) {
            std::panic::panic_any(format!("python crash at {i}"));
        }
        push(row(i + 1000));
        Ok(())
    }

    fn items(fail: Fail, n: usize) -> Vec<Result<usize>> {
        (0..n).map(|i| if fail == Fail::ErrItem(i) { Err(Error::msg("item")) } else { Ok(i) }).collect()
    }

    /// What python prints / raises: the serial loop.
    fn serial(r: &mut dyn RowSink, fail: Fail, n: usize) -> Result<()> {
        for item in items(fail, n) {
            let i = item?;
            let mut rows = Vec::new();
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(fail, i, &mut |v| rows.push(v))));
            for v in rows {
                r.row(0, v)?;
            }
            match res {
                Ok(r) => r?,
                Err(p) => std::panic::resume_unwind(p),
            }
        }
        Ok(())
    }

    fn outcome(res: std::thread::Result<Result<()>>) -> String {
        match res {
            Ok(Ok(())) => "ok".to_string(),
            Ok(Err(e)) => format!("err {e}"),
            Err(p) => format!("panic {}", p.downcast_ref::<String>().cloned().unwrap_or_default()),
        }
    }

    /// emit_par_blocks gives every renderer the serial output: the rows in item order, an `Err`
    /// item or a failing item ends the output right where python raised, and a panicking item's
    /// rows before the panic are emitted before the panic is resumed with its own payload.
    #[test]
    fn emit_par_blocks_like_serial() {
        let n = 500usize;
        for name in ["quick", "csv", "json", "jsonl", "pretty", "none"] {
            for fail in [Fail::None, Fail::ErrItem(0), Fail::ErrItem(333), Fail::ErrAfterRow(5), Fail::Panic(0), Fail::Panic(417)] {
                let run = |parallel: bool| -> (Vec<u8>, String) {
                    let mut buf = Vec::new();
                    let o;
                    {
                        let mut r = create(name, &mut buf, RenderOptions::default()).unwrap();
                        r.begin(crate::cols![("I", Int), ("S", Str)]).unwrap();
                        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if parallel { emit_par_blocks(&mut *r, items(fail, n), |&i, b| body(fail, i, &mut |v| b.push(v))) } else { serial(&mut *r, fail, n) }
                        }));
                        o = outcome(res);
                        if o == "ok" { r.finish().unwrap() } else { r.abort(false).unwrap() }
                    }
                    (buf, o)
                };
                let (want, wo) = run(false);
                let (got, go) = run(true);
                assert_eq!(wo, go, "{name} {fail:?}");
                assert!(want == got, "{name} {fail:?}: output differs");
            }
        }
        // no encoder (collectors, --filters): the values themselves, in order
        for fail in [Fail::None, Fail::ErrAfterRow(77), Fail::Panic(10)] {
            let mut a = CollectSink::default();
            let mut b = CollectSink::default();
            let ra = outcome(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serial(&mut a, fail, 200))));
            let rb = outcome(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| emit_par_blocks(&mut b, items(fail, 200), |&i, blk| body(fail, i, &mut |v| blk.push(v))))));
            assert_eq!(ra, rb);
            assert_eq!(format!("{:?}", a.rows), format!("{:?}", b.rows));
        }
    }
}
