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
/// `windows/<pdb_name>/<GUID>-<age>.json.xz`.
pub fn isf_relative_path(pdb_name: &str, guid: &str, age: u32) -> PathBuf {
    let mut p = PathBuf::from("windows");
    if !pdb_name.is_empty() {
        p.push(pdb_name);
    }
    p.push(format!("{}-{age}.json.xz", guid.to_uppercase()));
    p
}

/// xz block size of converted tables: the blocks are compressed in parallel, so a kernel ISF
/// (~7 MB of JSON) takes ~20 ms instead of ~150 ms as one block, for ~5% more output.
const XZ_BLOCK: usize = 512 << 10;

/// The `.xz` file of a converted table (python writes it with `lzma.open(path, "w")`; the
/// bytes differ, python reads either).
pub fn xz_isf(json: &[u8]) -> Vec<u8> {
    use crate::codecs::xz_enc::{XzEncoder, XzOptions};
    use std::io::Write;
    let opts = XzOptions { block_size: XZ_BLOCK, ..XzOptions::preset(6) };
    let mut e = XzEncoder::with_options(Vec::with_capacity(json.len() / 8 + 64), opts);
    // writing into a Vec cannot fail
    let _ = e.write_all(json);
    e.finish().unwrap_or_default()
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

/// The output file `<dir>/<rel>` in the first of `dirs` where it can be created (python opens
/// it before downloading and moves on to the next directory on a PermissionError); the file
/// is created under a temporary name in the same directory, to be renamed when complete.
/// Returns (final path, temporary path).
fn open_output(dirs: &[PathBuf], rel: &Path) -> Option<(PathBuf, PathBuf)> {
    dirs.iter().find_map(|d| {
        let path = d.join(rel);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        (path.parent().is_some_and(|p| std::fs::create_dir_all(p).is_ok()) && std::fs::File::create(&tmp).is_ok()).then_some((path, tmp))
    })
}

/// python `PDBUtility.download_pdb_isf`: in the first of `dirs` (python: `symbols.__path__`
/// in order) where `windows/<pdb_name>/<GUID>-<age>.json.xz` can be created, downloads the
/// PDB, converts it (`PdbReader(ctx, url, pdb_name).get_json()`) and writes the table
/// xz-compressed. Returns its path and the JSON (so the caller need not decompress it again).
/// Nothing but directories is left behind on failure.
pub fn download_and_convert(pdb_name: &str, guid: &str, age: u32, dirs: &[PathBuf], offline: bool) -> Result<(PathBuf, Vec<u8>)> {
    check_name(pdb_name)?;
    if offline {
        // python's PdbRetreiver does not go to the network then, and nothing is written
        return Err(Error::Unsatisfied(format!("offline mode: not downloading {pdb_name} {}{age}", guid.to_uppercase())));
    }
    let Some((path, tmp)) = open_output(dirs, &isf_relative_path(pdb_name, guid, age)) else {
        return Err(Error::Symbol(
            "Cannot write downloaded symbols, please add the appropriate symbols or add/modify a symbols directory that is writable".into(),
        ));
    };
    let res = (|| -> Result<Vec<u8>> {
        let pdb = download_pdb(pdb_name, guid, age, false)?;
        let json = {
            let _t = crate::util::trace::span("pdb conversion");
            super::pdb_to_isf_json_named(&pdb, Some(pdb_name))?.into_bytes()
        };
        drop(pdb);
        let xz = {
            let _t = crate::util::trace::span("pdb isf xz compression");
            xz_isf(&json)
        };
        std::fs::write(&tmp, &xz)?;
        std::fs::rename(&tmp, &path)?;
        Ok(json)
    })();
    match res {
        Ok(json) => Ok((path, json)),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
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
            PathBuf::from("windows/ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz")
        );
        assert!(download_pdb("x.pdb", "00", 1, true).is_err());
        assert!(download_and_convert("../x.pdb", "00", 1, &[PathBuf::from("/nonexistent")], true).is_err());
        // no writable directory: fails before any download
        let e = download_and_convert("x.pdb", "00", 1, &[PathBuf::from("/proc/rsvol-no")], false).unwrap_err();
        assert!(e.to_string().contains("Cannot write downloaded symbols"), "{e}");
    }

    /// python's choice of output directory: the first where the file can be created.
    #[test]
    fn first_writable_dir() {
        let base = std::env::temp_dir().join(format!("rsvol-pdbdl-{}", std::process::id()));
        let dirs = [PathBuf::from("/proc/rsvol-no"), base.join("a"), base.join("b")];
        let rel = isf_relative_path("k.pdb", "ab", 2);
        let (path, tmp) = open_output(&dirs, &rel).unwrap();
        assert_eq!(path, base.join("a/windows/k.pdb/AB-2.json.xz"));
        assert!(tmp.is_file() && tmp.parent() == path.parent());
        assert!(!base.join("b").exists());
        let _ = std::fs::remove_dir_all(&base);
        assert!(open_output(&dirs[..1], &rel).is_none());
    }

    #[test]
    fn xz_isf_roundtrips() {
        let json: Vec<u8> = (0..200_000u32).flat_map(|i| format!("{{\"k{}\": {}}},\n", i % 977, i % 13).into_bytes()).collect();
        let xz = xz_isf(&json);
        assert!(json.len() > 2 * XZ_BLOCK && xz.len() < json.len() / 4);
        assert_eq!(crate::codecs::xz::decompress(&xz).unwrap(), json);
    }
}
