//! python volatility3's full requirement list of every plugin (`get_requirements()`, python
//! order), hidden requirements included: the kernel `ModuleRequirement`, a plugin's own
//! `TranslationLayerRequirement`, its `VersionRequirement`s. [`Plugin::requirements`] lists only
//! the CLI-visible options; what python records in a saved configuration (`--save-config`,
//! `timeliner --record-config`) needs all of them.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! The data is `pyreqs.tsv`, generated from python itself by `bench/scripts/py_plugin_reqs.py`
//! (regenerate it rather than editing it); it is parsed on first use (only runs that save a
//! configuration need it).
//!
//! [`Plugin::requirements`]: super::Plugin::requirements

use crate::cli::json::{self, Json};
use std::sync::OnceLock;

/// The python requirement class (most specific).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyKind {
    Bool,
    Int,
    String,
    Uri,
    Bytes,
    List,
    Choice,
    /// `VersionRequirement` / `PluginRequirement`
    Version,
    /// `ModuleRequirement`
    Module,
    /// `TranslationLayerRequirement`
    Layer,
    /// `SymbolTableRequirement`
    Symbols,
    /// anything else (`MultiRequirement`, `ComplexListRequirement`, ...)
    Other,
}

/// One requirement of a python plugin.
#[derive(Clone, Debug)]
pub struct PyReq {
    pub name: &'static str,
    pub kind: PyKind,
    pub optional: bool,
    /// `requirement.default` (`Json::Null` for `None`)
    pub default: Json,
    /// List: the element type; Module / Layer: `architectures[;oses]`; Choice: the choices
    /// (JSON); else empty
    pub extra: &'static str,
    /// `requirement.description`
    pub description: String,
}

impl PyReq {
    /// A `TranslationLayerRequirement` / `ModuleRequirement` that only an Intel layer satisfies.
    pub fn needs_intel(&self) -> bool {
        self.extra.split(';').next().is_some_and(|a| a.split(',').any(|x| x.starts_with("Intel")))
    }
}

const TABLE: &str = include_str!("pyreqs.tsv");

fn parse() -> Vec<(&'static str, Vec<PyReq>)> {
    let mut out: Vec<(&'static str, Vec<PyReq>)> = Vec::new();
    for line in TABLE.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&'static str> = line.split('\t').collect();
        let [plugin, name, kind, optional, default, extra, description] = f[..] else { continue };
        if out.last().is_none_or(|(p, _)| *p != plugin) {
            out.push((plugin, Vec::new()));
        }
        let kind = match kind {
            "None" => continue,
            "Bool" => PyKind::Bool,
            "Int" => PyKind::Int,
            "String" => PyKind::String,
            "URI" => PyKind::Uri,
            "Bytes" => PyKind::Bytes,
            "List" => PyKind::List,
            "Choice" => PyKind::Choice,
            "Version" => PyKind::Version,
            "Module" => PyKind::Module,
            "Layer" => PyKind::Layer,
            "Symbols" => PyKind::Symbols,
            _ => PyKind::Other,
        };
        let description = match json::parse(description) {
            Ok(Json::Str(s)) => s,
            _ => String::new(),
        };
        let reqs = &mut out.last_mut().expect("pushed above").1;
        reqs.push(PyReq { name, kind, optional: optional == "1", default: json::parse(default).unwrap_or(Json::Null), extra, description });
    }
    out
}

fn table() -> &'static [(&'static str, Vec<PyReq>)] {
    static T: OnceLock<Vec<(&'static str, Vec<PyReq>)>> = OnceLock::new();
    T.get_or_init(parse)
}

/// python's requirements of the plugin registered as `plugin` (e.g. `"windows.pslist.PsList"`),
/// in `get_requirements()` order; `None` for a plugin python does not have.
pub fn requirements(plugin: &str) -> Option<&'static [PyReq]> {
    let t = table();
    t.binary_search_by(|(p, _)| (*p).cmp(plugin)).ok().map(|i| t[i].1.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_complete() {
        let t = table();
        assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "pyreqs.tsv must be sorted by plugin");
        // every registered plugin has python's requirement list, and vice versa
        let ours: Vec<&str> = crate::plugins::all().iter().map(|p| p.name()).collect();
        for p in &ours {
            assert!(requirements(p).is_some(), "{p} missing from pyreqs.tsv");
        }
        for (p, _) in t {
            assert!(ours.contains(p), "{p} in pyreqs.tsv but not registered");
        }
        let pslist = requirements("windows.pslist.PsList").unwrap();
        assert_eq!(pslist[0].name, "kernel");
        assert_eq!(pslist[0].kind, PyKind::Module);
        assert!(pslist[0].needs_intel());
        assert!(requirements("frameworkinfo.FrameworkInfo").unwrap().is_empty());
        let mp = requirements("mac.pslist.PsList").unwrap().iter().find(|r| r.name == "pslist_method").unwrap();
        assert_eq!((mp.kind, &mp.default), (PyKind::Choice, &Json::Str("tasks".into())));
    }

    /// Every CLI-visible requirement of a plugin is one of python's, with python's kind.
    #[test]
    fn cli_requirements_match_python() {
        use crate::plugins::ReqKind;
        for p in crate::plugins::all() {
            let py = requirements(p.name()).unwrap();
            for r in p.requirements() {
                let Some(q) = py.iter().find(|q| q.name == r.name) else {
                    panic!("{}: {} is not a python requirement", p.name(), r.name)
                };
                let ok = match r.kind {
                    ReqKind::Bool => q.kind == PyKind::Bool,
                    ReqKind::Int => q.kind == PyKind::Int,
                    ReqKind::Str => q.kind == PyKind::String,
                    ReqKind::Bytes => q.kind == PyKind::Bytes,
                    ReqKind::Uri => q.kind == PyKind::Uri,
                    ReqKind::ListInt => q.kind == PyKind::List && q.extra == "int",
                    ReqKind::ListStr => q.kind == PyKind::List && q.extra == "str",
                    ReqKind::Choice(_) => q.kind == PyKind::Choice,
                };
                assert!(ok, "{}: {} is {:?} in fastvol, {:?} in python", p.name(), r.name, r.kind, q.kind);
            }
        }
    }

    /// Every CLI-visible requirement has python's default and optionality: the CLI's argparse
    /// default is `requirement.default`, and python records a configured value (not `None`)
    /// in a saved configuration.
    #[test]
    fn cli_defaults_match_python() {
        let mut bad = Vec::new();
        for p in crate::plugins::all() {
            let py = requirements(p.name()).unwrap();
            for r in p.requirements() {
                let q = py.iter().find(|q| q.name == r.name).unwrap();
                let ours = r.default.as_ref().map_or(Json::Null, crate::cli::cv_to_json);
                if ours != q.default || r.optional != q.optional {
                    bad.push(format!("{} {}: fastvol {:?} optional={}, python {:?} optional={}", p.name(), r.name, ours, r.optional, q.default, q.optional));
                }
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }
}
