//! fastvol's own environment variables: `FASTVOL_<NAME>`, with `RSVOL_<NAME>` (the project's
//! former name) still accepted as an alias; `FASTVOL_<NAME>` wins when both are set.
//!
//! The environment is read once per process: the first lookup makes one pass over `environ`
//! (what a single `getenv` costs) and keeps the few variables with either prefix, usually none.
//! Every lookup after that is a search of that short list, with no `getenv` (each of which
//! scans the whole environment, ~200 variables in a desktop session) and no lock. fastvol never
//! changes its own environment (no `set_var` / `remove_var` anywhere), so the snapshot cannot
//! go stale; callers still read each setting once where it matters.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// The current prefix.
pub const PREFIX: &str = "FASTVOL_";
/// The former prefix, still accepted.
pub const LEGACY_PREFIX: &str = "RSVOL_";

struct Var {
    /// the name after the prefix
    name: Box<[u8]>,
    value: &'static OsStr,
    legacy: bool,
}

fn vars() -> &'static [Var] {
    static V: std::sync::OnceLock<Vec<Var>> = std::sync::OnceLock::new();
    V.get_or_init(scan)
}

fn scan() -> Vec<Var> {
    unsafe extern "C" {
        static mut environ: *const *const std::ffi::c_char;
    }
    let mut out = Vec::new();
    // SAFETY: `environ` is libc's NULL-terminated array of NUL-terminated "NAME=value" strings,
    // and nothing in this process modifies the environment, so it is stable while it is read.
    unsafe {
        let mut p = environ;
        if p.is_null() {
            return out;
        }
        while !(*p).is_null() {
            let e = (*p).cast::<u8>();
            p = p.add(1);
            let (prefix, legacy) = match *e {
                b'F' => (PREFIX.as_bytes(), false),
                b'R' => (LEGACY_PREFIX.as_bytes(), true),
                _ => continue,
            };
            // byte by byte: a shorter string ends at its NUL, which never matches
            if !prefix.iter().enumerate().all(|(i, &c)| *e.add(i) == c) {
                continue;
            }
            let s = std::ffi::CStr::from_ptr(e.cast()).to_bytes();
            let rest = &s[prefix.len()..];
            if let Some(eq) = rest.iter().position(|&c| c == b'=') {
                // leaked once per matching variable (a handful at most), for `&'static` values
                let value: &'static [u8] = Box::leak(rest[eq + 1..].to_vec().into_boxed_slice());
                out.push(Var { name: rest[..eq].into(), value: OsStr::from_bytes(value), legacy });
            }
        }
    }
    out
}

/// The value of `FASTVOL_<name>`, else of `RSVOL_<name>` (the first definition of each, like
/// `getenv`). `name` is given without the prefix.
pub fn get(name: &str) -> Option<&'static OsStr> {
    let all = vars();
    let find = |legacy: bool| all.iter().find(|v| v.legacy == legacy && *v.name == *name.as_bytes()).map(|v| v.value);
    find(false).or_else(|| find(true))
}

/// [`get`] as `std::env::var_os` returns it.
pub fn var_os(name: &str) -> Option<OsString> {
    get(name).map(OsStr::to_os_string)
}

/// [`get`] as `std::env::var` returns it.
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    match get(name) {
        None => Err(std::env::VarError::NotPresent),
        Some(v) => v.to_str().map(str::to_string).ok_or_else(|| std::env::VarError::NotUnicode(v.to_os_string())),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prefixes_and_precedence() {
        // the test harness's environment: whatever it holds, lookups agree with std's view
        for (k, _) in std::env::vars_os() {
            let Some(k) = k.to_str() else { continue };
            let name = k.strip_prefix(super::PREFIX).or_else(|| k.strip_prefix(super::LEGACY_PREFIX));
            if let Some(name) = name.filter(|n| !n.is_empty()) {
                let want = std::env::var_os(format!("{}{name}", super::PREFIX))
                    .or_else(|| std::env::var_os(format!("{}{name}", super::LEGACY_PREFIX)));
                assert_eq!(super::var_os(name), want, "{k}");
            }
        }
        assert_eq!(super::get("NO_SUCH_VARIABLE_EVER_0123"), None);
        assert!(matches!(super::var("NO_SUCH_VARIABLE_EVER_0123"), Err(std::env::VarError::NotPresent)));
    }
}
