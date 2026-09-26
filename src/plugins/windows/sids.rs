//! The `sids_and_privileges.json` tables shipped with volatility3's windows plugins
//! (well-known SIDs, service SIDs, SID regexes, privilege names), used by `getsids`,
//! `getservicesids` and `privileges`. Embedded at build time, parsed once on first use.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::cli::regex::Regex;
use crate::util::json::Json;
use crate::util::{FxHashMap, FxHashSet};
use std::sync::OnceLock;

static RAW: &str = include_str!("../../../data/plugins/windows/sids_and_privileges.json");

/// The parsed tables (python dict semantics: a duplicated key keeps its last value).
pub struct SidsData {
    /// `["well known"]`: SID string -> name.
    pub well_known: FxHashMap<String, String>,
    /// `["service sids"]`: SID string -> service name.
    pub service_sids: FxHashMap<String, String>,
    /// `set(["service sids"].values())`.
    pub service_names: FxHashSet<String>,
    /// `["sids re"]`: (compiled python `re` pattern, name), in file order.
    pub sids_re: Vec<(Regex, String)>,
    /// `["privileges"]` keyed by `int(key)`: (name, description).
    pub privileges: FxHashMap<i128, (String, String)>,
}

fn str_map(j: Option<&Json>) -> FxHashMap<String, String> {
    let mut m = FxHashMap::default();
    for (k, v) in j.and_then(|j| j.as_object()).unwrap_or(&[]) {
        if let Some(s) = v.as_str() {
            m.insert(k.to_string(), s.to_string());
        }
    }
    m
}

/// The embedded tables.
pub fn data() -> &'static SidsData {
    static D: OnceLock<SidsData> = OnceLock::new();
    D.get_or_init(|| {
        let j = Json::parse(RAW.as_bytes()).expect("embedded sids_and_privileges.json");
        let well_known = str_map(j.get("well known"));
        let service_sids = str_map(j.get("service sids"));
        let service_names = service_sids.values().cloned().collect();
        let mut sids_re = Vec::new();
        for e in j.get("sids re").and_then(|a| a.as_array()).unwrap_or(&[]) {
            let a = e.as_array().unwrap_or(&[]);
            if let (Some(p), Some(n)) = (a.first().and_then(|p| p.as_str()), a.get(1).and_then(|n| n.as_str())) {
                if let Ok(r) = Regex::new(p) {
                    sids_re.push((r, n.to_string()));
                }
            }
        }
        let mut privileges = FxHashMap::default();
        for (k, v) in j.get("privileges").and_then(|p| p.as_object()).unwrap_or(&[]) {
            let a = v.as_array().unwrap_or(&[]);
            if let (Ok(n), Some(name), Some(desc)) =
                (k.trim().parse::<i128>(), a.first().and_then(|x| x.as_str()), a.get(1).and_then(|x| x.as_str()))
            {
                privileges.insert(n, (name.to_string(), desc.to_string()));
            }
        }
        SidsData { well_known, service_sids, service_names, sids_re, privileges }
    })
}

/// python `getsids.find_sid_re(sid_string, sid_re_list)`: the name of the first pattern that
/// `re.search`es `sid`, or None (python's `NotAvailableValue`).
pub fn find_sid_re(sid: &str) -> Option<&'static str> {
    data().sids_re.iter().find(|(r, _)| r.is_match(sid)).map(|(_, n)| n.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tables() {
        let d = data();
        assert_eq!(d.well_known.len(), 86);
        assert_eq!(d.service_sids.len(), 461);
        assert_eq!(d.sids_re.len(), 20);
        assert_eq!(d.privileges.len(), 35);
        assert_eq!(d.privileges[&2].0, "SeCreateTokenPrivilege");
        assert_eq!(find_sid_re("S-1-5-21-1-2-3-500"), Some("Administrator"));
        assert_eq!(find_sid_re("S-1-5-5-0-12345"), Some("Logon Session"));
        assert_eq!(find_sid_re("S-1-5-18"), None);
    }
}
