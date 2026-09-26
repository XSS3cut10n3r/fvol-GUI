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
use std::collections::HashMap;

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

/// Values for one plugin run (CLI options after parsing, defaults applied).
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub values: HashMap<String, ConfigValue>,
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
    /// Text shown in the `vol -h` plugin list (python class docstring, first paragraph).
    /// Empty when the python class has no docstring.
    fn description(&self) -> &'static str;
    /// The rest of the python docstring after the first blank line (argparse epilog of
    /// `vol <plugin> -h`), if any.
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

/// Every registered plugin, sorted by name.
pub fn all() -> Vec<&'static dyn Plugin> {
    let mut v: Vec<&'static dyn Plugin> = Vec::new();
    generic::register(&mut v);
    windows::register(&mut v);
    linux::register(&mut v);
    mac::register(&mut v);
    // Sorted by name. Every run pays for this, so compare cached keys: the first 16 name bytes
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
/// [`RowBlock`] (formatted on the worker when `out` has a row encoder); the blocks come back
/// in index order with `f`'s results, for the caller to [`RowBlock::emit`] in python's order.
pub fn par_blocks<'e, X: Send>(enc: Option<&'e crate::renderers::text::RowEncoder>, n: usize, f: impl Fn(usize, &mut RowBlock<'e>) -> X + Sync) -> Vec<(RowBlock<'e>, X)> {
    crate::util::par::par_map(n, |i| {
        let mut b = RowBlock::new(enc);
        let x = f(i, &mut b);
        (b, x)
    })
}

/// python `for item in items: yield from rows(item)` with the items' rows computed (and
/// formatted, see [`RowBlock`]) in parallel and emitted in order. An `Err` item = python raised
/// there (before its rows); `f` returning `Err` = python raised after the rows it pushed.
pub fn emit_par_blocks<T: Sync>(out: &mut dyn RowSink, items: Vec<Result<T>>, f: impl Fn(&T, &mut RowBlock) -> Result<()> + Sync) -> Result<()> {
    let enc = out.encoder();
    let blocks = par_blocks(enc.as_ref(), items.len(), |i, b| match &items[i] {
        Ok(t) => f(t, b).err(),
        Err(_) => None,
    });
    for (item, (b, err)) in items.into_iter().zip(blocks) {
        item?;
        b.emit(out)?;
        if let Some(e) = err {
            return Err(e);
        }
    }
    Ok(())
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
