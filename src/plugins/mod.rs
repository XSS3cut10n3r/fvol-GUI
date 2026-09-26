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
//!     kernel/layers/symbols lazily from the `Context`.
//!   * `run()` writes columns then rows into the sink (see `renderers` contract).

pub mod generic;
pub mod linux;
pub mod mac;
pub mod windows;

use crate::context::Context;
use crate::error::Result;
use crate::renderers::{RowSink, Value};
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

/// Every registered plugin, sorted by name.
pub fn all() -> Vec<&'static dyn Plugin> {
    let mut v: Vec<&'static dyn Plugin> = Vec::new();
    generic::register(&mut v);
    windows::register(&mut v);
    linux::register(&mut v);
    mac::register(&mut v);
    v.sort_by(|a, b| a.name().cmp(b.name()));
    v
}

/// Look up a plugin by its full name.
pub fn find(name: &str) -> Option<&'static dyn Plugin> {
    all().into_iter().find(|p| p.name() == name)
}
