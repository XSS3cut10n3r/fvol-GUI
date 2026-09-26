//! Remote files (python `ResourceAccessor`, framework/layers/resources.py): a `http://`,
//! `https://` or `ftp://` location is downloaded once with `curl` into rsvol's cache directory
//! as `data_<sha512(url)>.cache` (python's name, in python's `CACHE_PATH` layout) and read from
//! there; like python, a cached file is never re-validated, and `--clear-cache` deletes it.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::util::paths;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether `url` names a location rsvol downloads (python opens these through urllib).
pub fn is_remote(url: &str) -> bool {
    let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    ["http://", "https://", "ftp://"].iter().any(|s| lower.starts_with(s))
}

/// python `bytes(s, "raw_unicode_escape")`: code points below 256 as one byte, others as
/// `\uXXXX` / `\UXXXXXXXX` (lower-case hex).
pub fn raw_unicode_escape(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let v = c as u32;
        if v < 0x100 {
            out.push(v as u8);
        } else if v < 0x10000 {
            out.extend_from_slice(format!("\\u{v:04x}").as_bytes());
        } else {
            out.extend_from_slice(format!("\\U{v:08x}").as_bytes());
        }
    }
    out
}

/// The cache file of `url`: `<rsvol cache>/data_<sha512 hex>.cache`.
pub fn cache_path(url: &str) -> PathBuf {
    let d = crate::crypto::sha512::digest(&raw_unicode_escape(url));
    paths::rsvol_cache_dir().join(format!("data_{}.cache", paths::hex(&d)))
}

/// The local copy of remote `url`, downloading it on first use. Fails in offline mode (python
/// raises `OfflineException` for http(s) then, cached or not).
pub fn fetch(url: &str, offline: bool) -> Result<PathBuf> {
    if offline {
        return Err(Error::Msg(format!("Volatility 3 is offline: unable to access {url}")));
    }
    let path = cache_path(url);
    if path.is_file() {
        return Ok(path);
    }
    download_to(url, &path)?;
    Ok(path)
}

/// Downloads `url` into `dest` (atomically: a temporary file in the same directory, renamed
/// once complete; nothing is left behind on failure).
pub fn download_to(url: &str, dest: &Path) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = dest.with_extension(format!("part{}", std::process::id()));
    let r = curl_to_file(url, &tmp, false).or_else(|e| match e {
        // python: on a certificate verification failure it warns and retries unverified
        CurlError::Cert(_) => {
            eprintln!("WARNING  volatility3.framework.layers.resources: SSL certificate verification failed: attempting UNVERIFIED retrieval");
            curl_to_file(url, &tmp, true)
        }
        e => Err(e),
    });
    match r.and_then(|()| std::fs::rename(&tmp, dest).map_err(|e| CurlError::Other(e.to_string()))) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(Error::Msg(match e {
                CurlError::Cert(m) | CurlError::Other(m) => format!("download of {url} failed: {m}"),
            }))
        }
    }
}

enum CurlError {
    /// curl exit 60: the peer certificate could not be verified
    Cert(String),
    Other(String),
}

fn curl_to_file(url: &str, out: &Path, insecure: bool) -> std::result::Result<(), CurlError> {
    let mut c = Command::new("curl");
    c.args(["--fail", "--silent", "--show-error", "--location", "--globoff", "--connect-timeout", "30"]);
    if insecure {
        c.arg("--insecure");
    }
    c.arg("--output").arg(out).args(["--", url]);
    let r = c.output().map_err(|e| CurlError::Other(format!("cannot run curl: {e}")))?;
    if r.status.success() {
        return Ok(());
    }
    let msg = String::from_utf8_lossy(&r.stderr).trim().to_string();
    if r.status.code() == Some(60) { Err(CurlError::Cert(msg)) } else { Err(CurlError::Other(msg)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_cache_names() {
        // python: hashlib.sha512(bytes(url, "raw_unicode_escape")).hexdigest()
        let u = "http://127.0.0.1:8000/x \u{e9}\u{20ac}\u{1F600}\\";
        assert_eq!(raw_unicode_escape(u), b"http://127.0.0.1:8000/x \xe9\\u20ac\\U0001f600\\".to_vec());
        let name = cache_path(u);
        assert_eq!(
            name.file_name().unwrap().to_str().unwrap(),
            "data_b3026eac48518f1815a739f3357f083de48a5ba2d7549be0302863b59acd4307a6586cad6c6fed3c2f803156dbbb7abc352c5b05d94c873d963695337a1654fd.cache"
        );
        assert!(is_remote("http://a/b") && is_remote("HTTPS://a") && is_remote("ftp://x"));
        assert!(!is_remote("file:///x") && !is_remote("/tmp/http://x") && !is_remote("jar:file:/x!y"));
        assert!(fetch("http://127.0.0.1:1/x", true).is_err());
    }
}
