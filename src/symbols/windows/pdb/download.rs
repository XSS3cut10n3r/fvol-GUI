// Derived from Volatility 3 (Volatility Software License 1.0):
// framework/symbols/windows/pdbconv.py (PdbRetreiver), pdbutil.py (download_pdb_isf)
//! Microsoft symbol server download (via `curl`) and PDB -> ISF caching.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// volatility3 `constants.SYMBOL_SERVER_URL`.
pub const SYMBOL_SERVER_URL: &str = "http://msdl.microsoft.com/download/symbols";

/// The URLs `PdbRetreiver.retreive_pdb(guid + str(age), file_name=pdb_name)` tries, in order:
/// `<server>/<name>.pdb/<GUID><age>/<name>.pdb` then the compressed `<name>.pd_` variant.
/// Like python, the extension is forced to "pdb" and the age is written in decimal.
pub fn symbol_server_urls(pdb_name: &str, guid: &str, age: u32) -> Vec<String> {
    // ".".join(file_name.split(".")[:-1] + ["pdb"])
    let mut parts: Vec<&str> = pdb_name.split('.').collect();
    parts.pop();
    parts.push("pdb");
    let file_name = parts.join(".");
    let url = format!("{SYMBOL_SERVER_URL}/{file_name}/{}{age}/", guid.to_uppercase());
    let compressed = format!("{}_", &file_name[..file_name.len() - 1]);
    vec![format!("{url}{file_name}"), format!("{url}{compressed}")]
}

/// Where python's `download_pdb_isf` stores the converted table below a symbols directory:
/// `windows/<pdb_name>/<GUID>-<age>.json` (python appends ".xz"; rsvol writes plain JSON).
pub fn isf_relative_path(pdb_name: &str, guid: &str, age: u32) -> PathBuf {
    let mut p = PathBuf::from("windows");
    if !pdb_name.is_empty() {
        p.push(pdb_name);
    }
    p.push(format!("{}-{age}.json", guid.to_uppercase()));
    p
}

fn check_name(pdb_name: &str) -> Result<()> {
    if pdb_name.contains(['/', '\\', '\0']) || pdb_name == "." || pdb_name == ".." {
        return Err(Error::Symbol(format!("refusing suspicious PDB name {pdb_name:?}")));
    }
    Ok(())
}

/// GETs `url` with curl (following redirects); Err on transport or HTTP errors.
fn curl_get(url: &str) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location", "--globoff"])
        .args(["--connect-timeout", "30", "--retry", "2", "--output", "-", "--", url])
        .output()
        .map_err(|e| Error::Msg(format!("cannot run curl: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Msg(format!("download of {url} failed: {}", err.trim())));
    }
    Ok(out.stdout)
}

/// Downloads a PDB from the Microsoft symbol server (python `PdbRetreiver.retreive_pdb` +
/// reading the file). Returns the raw bytes of the first URL that succeeds (a `.pd_`
/// fallback is returned as-is: like python, CAB-compressed files are not unpacked, so they
/// fail to convert).
pub fn download_pdb(pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<Vec<u8>> {
    if offline {
        return Err(Error::Unsatisfied(format!(
            "offline mode: not downloading {pdb_name} {}{age}",
            guid.to_uppercase()
        )));
    }
    let mut last_err = None;
    for url in symbol_server_urls(pdb_name, guid, age) {
        match curl_get(&url) {
            Ok(data) if !data.is_empty() => return Ok(data),
            Ok(_) => last_err = Some(Error::Msg(format!("empty response from {url}"))),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::msg("PDB file could not be retrieved from the internet")))
}

/// python `PDBUtility.download_pdb_isf`: downloads the PDB, converts it
/// (`PdbReader(ctx, url, pdb_name).get_json()`) and writes
/// `<dest_dir>/windows/<pdb_name>/<GUID>-<age>.json`, returning its path. Nothing is left
/// behind on failure.
pub fn download_and_convert(pdb_name: &str, guid: &str, age: u32, dest_dir: &Path, offline: bool) -> Result<PathBuf> {
    check_name(pdb_name)?;
    let path = dest_dir.join(isf_relative_path(pdb_name, guid, age));
    let pdb = download_pdb(pdb_name, guid, age, offline)?;
    let json = super::pdb_to_isf_json_named(&pdb, Some(pdb_name))?;
    drop(pdb);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("json.tmp{}", std::process::id()));
    let res = std::fs::write(&tmp, json.as_bytes()).and_then(|_| std::fs::rename(&tmp, &path));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_like_python() {
        let u = symbol_server_urls("ntkrnlmp.pdb", "8e3373d6124e747f0e72ef8e02e676b3", 1);
        assert_eq!(
            u,
            vec![
                "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B31/ntkrnlmp.pdb",
                "http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B31/ntkrnlmp.pd_",
            ]
        );
        // python quirks: extension forced to pdb, decimal age
        let u = symbol_server_urls("tcpip.sys", "AB", 12);
        assert_eq!(u[0], "http://msdl.microsoft.com/download/symbols/tcpip.pdb/AB12/tcpip.pdb");
        let u = symbol_server_urls("noext", "AB", 1);
        assert_eq!(u[0], "http://msdl.microsoft.com/download/symbols/pdb/AB1/pdb");
        assert_eq!(u[1], "http://msdl.microsoft.com/download/symbols/pdb/AB1/pd_");
    }

    #[test]
    fn paths_and_offline() {
        assert_eq!(
            isf_relative_path("ntkrnlmp.pdb", "8e3373d6124e747f0e72ef8e02e676b3", 1),
            PathBuf::from("windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json")
        );
        assert!(download_pdb("x.pdb", "00", 1, true).is_err());
        assert!(download_and_convert("../x.pdb", "00", 1, Path::new("/nonexistent"), true).is_err());
    }
}
