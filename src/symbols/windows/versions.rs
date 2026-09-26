//! python `symbols/windows/versions.py`: Windows version distinguishers.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! if versions::IS_WIN10.check(kernel.table) { ... }
//! ```

use crate::symbols::SymbolTable;
use std::cmp::Ordering;

/// python tuple comparison (`(10, 0) <= (10, 0, 19041, 1)`).
pub fn cmp_tuple(a: &[i64], b: &[i64]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        match x.cmp(y) {
            Ordering::Equal => continue,
            o => return o,
        }
    }
    a.len().cmp(&b.len())
}

/// A version predicate over the (major, minor, revision, build) tuple.
#[derive(Clone, Copy)]
pub enum VersionCheck {
    /// `lo <= x < hi` (either bound optional)
    Range(Option<&'static [i64]>, Option<&'static [i64]>),
    /// `x == v`
    Eq(&'static [i64]),
}

impl VersionCheck {
    fn test(&self, x: &[i64]) -> bool {
        match self {
            VersionCheck::Range(lo, hi) => {
                lo.is_none_or(|l| cmp_tuple(l, x) != Ordering::Greater) && hi.is_none_or(|h| cmp_tuple(x, h) == Ordering::Less)
            }
            VersionCheck::Eq(v) => cmp_tuple(x, v) == Ordering::Equal,
        }
    }
}

/// python `OsDistinguisher(version_check, fallback_checks)`.
pub struct OsDistinguisher {
    pub version_check: VersionCheck,
    /// (symbol or type name, member name, must be present)
    pub fallback_checks: &'static [(&'static str, Option<&'static str>, bool)],
}

impl OsDistinguisher {
    /// python `distinguisher(context, symbol_table)`.
    pub fn check(&self, table: &SymbolTable) -> bool {
        // primary: metadata.windows.pe = {major, minor, revision, build} (ISF >= 6.0 only)
        if table.format().0 >= 6 {
            if let Some(pe) = table.metadata().path(&["windows", "pe"]) {
                let g = |k: &str| pe.get(k).and_then(|v| v.as_i64());
                if let (Some(ma), Some(mi), Some(re), Some(bu)) = (g("major"), g("minor"), g("revision"), g("build")) {
                    return self.version_check.test(&[ma, mi, re, bu]);
                }
            }
        }
        for &(name, member, response) in self.fallback_checks {
            match member {
                None => {
                    if (table.has_symbol(name) || table.has_type(name)) != response {
                        return false;
                    }
                }
                Some(m) => match table.user_type(name) {
                    Some(ut) => {
                        if table.member(ut, m).is_some() != response {
                            return false;
                        }
                    }
                    None => {
                        // natives have no members; unknown type -> SymbolError
                        if table.get_type(name).is_ok() {
                            if response {
                                return false;
                            }
                        } else if !response {
                            return false;
                        }
                    }
                },
            }
        }
        true
    }
}

macro_rules! dist {
    ($name:ident, $check:expr, [$(($n:expr, $m:expr, $r:expr)),* $(,)?]) => {
        pub const $name: OsDistinguisher = OsDistinguisher { version_check: $check, fallback_checks: &[$(($n, $m, $r)),*] };
    };
}

use VersionCheck::{Eq, Range};

dist!(IS_WINDOWS_XP, Range(Some(&[5, 1]), Some(&[5, 2])), [("KdCopyDataBlock", None, false), ("_HANDLE_TABLE", Some("HandleCount"), true)]);
dist!(IS_WINDOWS_XP_SP2, Range(Some(&[5, 1]), Some(&[5, 2])), [
    ("KdCopyDataBlock", None, false),
    ("_MMFREE_POOL_ENTRY", None, false),
    ("_HANDLE_TABLE", Some("HandleCount"), true)
]);
dist!(IS_WINDOWS_XP_SP3, Range(Some(&[5, 1]), Some(&[5, 2])), [
    ("KdCopyDataBlock", None, false),
    ("_MMFREE_POOL_ENTRY", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), true)
]);
dist!(IS_XP_OR_2003, Range(Some(&[5, 1]), Some(&[6, 0])), [("KdCopyDataBlock", None, false), ("_HANDLE_TABLE", Some("HandleCount"), true)]);
dist!(IS_2003, Range(Some(&[5, 2]), Some(&[5, 3])), [
    ("KdCopyDataBlock", None, false),
    ("_HANDLE_TABLE", Some("HandleCount"), true),
    ("_MM_AVL_TABLE", None, true)
]);
dist!(IS_VISTA_OR_LATER, Range(Some(&[6, 0]), None), [("KdCopyDataBlock", None, true)]);
dist!(IS_WINDOWS_8_1_OR_LATER, Range(Some(&[6, 3]), None), [("_KPRCB", Some("PendingTickFlags"), true)]);
dist!(IS_WIN10, Range(Some(&[10, 0]), None), [("ObHeaderCookie", None, true), ("_HANDLE_TABLE", Some("HandleCount"), false)]);
dist!(IS_WIN10_10586_OR_LATER, Range(Some(&[10, 0, 10586]), None), [("_UNLOADED_DRIVERS", None, false), ("ObHeaderCookie", None, true)]);
dist!(IS_WIN10_UP_TO_15063, Range(Some(&[10, 0]), Some(&[10, 0, 15063])), [
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), true)
]);
dist!(IS_WIN10_15063, Eq(&[10, 0, 15063]), [
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false),
    ("_EPROCESS", Some("ControlFlowGuardEnabled"), true)
]);
dist!(IS_WIN10_15063_OR_LATER, Range(Some(&[10, 0, 15063]), None), [
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false)
]);
dist!(IS_WIN10_16299_OR_LATER, Range(Some(&[10, 0, 16299]), None), [
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false),
    ("_EPROCESS", Some("ControlFlowGuardEnabled"), false)
]);
dist!(IS_WIN10_17134_OR_LATER, Range(Some(&[10, 0, 17134]), None), [
    ("_EPROCESS", Some("ProcessFirstResume"), true),
    ("_EPROCESS", Some("HighMemoryPriority"), true)
]);
dist!(IS_WIN10_17735_OR_LATER, Range(Some(&[10, 0, 17735]), None), [
    ("_EPROCESS", Some("VmProcessorHost"), true),
    ("_EPROCESS", Some("VdmObjects"), false)
]);
dist!(IS_WIN10_17763_OR_LATER, Range(Some(&[10, 0, 17763]), None), [
    ("_EPROCESS", Some("TrustletIdentity"), false),
    ("ParentSecurityDomain", None, true)
]);
dist!(IS_WIN10_18362_OR_LATER, Range(Some(&[10, 0, 18362]), None), [
    ("ObHeaderCookie", None, true),
    ("_CM_CACHED_VALUE_INDEX", None, false),
    ("_WNF_PROCESS_CONTEXT", None, true)
]);
dist!(IS_WIN10_18363_OR_LATER, Range(Some(&[10, 0, 18363]), None), [("_KQOS_GROUPING_SETS", None, true)]);
dist!(IS_WIN10_19041_OR_LATER, Range(Some(&[10, 0, 19041]), None), [
    ("_EPROCESS", Some("TimerResolutionIgnore"), true),
    ("_EPROCESS", Some("VmProcessorHostTransition"), true),
    ("_KQOS_GROUPING_SETS", None, true)
]);
dist!(IS_WIN10_19577_OR_LATER, Range(Some(&[10, 0, 19577]), None), [
    ("_EPROCESS", Some("PaeTop"), false),
    ("_EPROCESS", Some("IdealProcessorAssignmentBlock"), true)
]);
dist!(IS_WIN10_25398_OR_LATER, Range(Some(&[10, 0, 25398]), None), [
    ("_EPROCESS", Some("MmSlabIdentity"), true),
    ("_EPROCESS", Some("EnableProcessImpersonationLogging"), true)
]);
dist!(IS_WINDOWS_10, Range(Some(&[10, 0]), None), [("ObHeaderCookie", None, true)]);
dist!(IS_WINDOWS_8_OR_LATER, Range(Some(&[6, 2]), None), [("_HANDLE_TABLE", Some("HandleCount"), false)]);
dist!(IS_WINDOWS_7_SP0, Eq(&[6, 1, 7600]), [
    ("_EPROCESS", Some("VdmObjects"), true),
    ("_EPROCESS", Some("UmsScheduledThreads"), false),
    ("_EPROCESS", Some("QuotaUsage"), false),
    ("_EPROCESS", Some("WnfContext"), false)
]);
dist!(IS_WINDOWS_7_SP1, Eq(&[6, 1, 7601]), [
    ("_EPROCESS", Some("VdmObjects"), false),
    ("_EPROCESS", Some("UmsScheduledThreads"), true),
    ("_EPROCESS", Some("QuotaUsage"), false),
    ("_EPROCESS", Some("WnfContext"), false)
]);
dist!(IS_WINDOWS_7, Eq(&[6, 1]), [("_OBJECT_HEADER", Some("TypeIndex"), true), ("_HANDLE_TABLE", Some("HandleCount"), true)]);
