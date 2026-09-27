// Derived from Volatility 3 (Volatility Software License 1.0):
// framework/symbols/windows/pdbconv.py (PdbRetreiver), pdbutil.py (download_pdb_isf)
//! Microsoft symbol server download (via `curl`) and PDB -> ISF caching. The downloaded PDB
//! stays in python's cache directory under python's name for it, `data_<sha512(url)>.cache`
//! (python's `ResourceAccessor` caches it there and `download_pdb_isf` only removes local
//! temporary files), and is reused instead of downloaded again.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

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

/// python's cache directory (`constants.CACHE_PATH` after `--cache-path`) and whether files
/// already in it may be used (not after `--clear-cache`, which makes python delete them
/// first). Set by `Context::new`; unset: `~/.cache/volatility3`, reused.
static PY_CACHE: std::sync::RwLock<Option<(PathBuf, bool)>> = std::sync::RwLock::new(None);

/// Sets where downloaded PDBs are kept (python's cache directory) and whether a PDB found
/// there is used instead of downloading it again.
pub fn set_python_cache(dir: PathBuf, reuse: bool) {
    *PY_CACHE.write().unwrap_or_else(|e| e.into_inner()) = Some((dir, reuse));
}

fn python_cache() -> (PathBuf, bool) {
    PY_CACHE.read().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| (crate::util::paths::vol3_cache_dir(None), true))
}

/// Where python's `ResourceAccessor` keeps the download of `url`:
/// `<CACHE_PATH>/data_<sha512(url)>.cache`.
pub fn pdb_cache_path(cache_dir: &Path, url: &str) -> PathBuf {
    let d = crate::crypto::sha512::digest(&crate::util::download::raw_unicode_escape(url));
    cache_dir.join(format!("data_{}.cache", crate::util::paths::hex(&d)))
}

/// Downloads a PDB from the Microsoft symbol server (python `PdbRetreiver.retreive_pdb`):
/// the first of [`symbol_server_urls`] that succeeds is kept in python's cache directory
/// under python's name for it (see [`pdb_cache_path`]), where python finds it too. A PDB
/// already there is not downloaded again. Returns the file (a `.pd_` fallback is kept
/// as-is: like python, CAB-compressed files are not unpacked, so they fail to convert).
pub fn fetch_pdb(pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<PathBuf> {
    let (dir, reuse) = python_cache();
    fetch_pdb_in(&dir, reuse, pdb_name, guid, age, offline)
}

/// Downloads of this process by cache file: one lock per file (a fetch waits for a download of
/// the same file in progress, e.g. a speculative [`prefetch`]) holding whether this process
/// downloaded it (then it is used even where older downloads are not, after `--clear-cache`).
fn fetch_lock(path: &Path) -> std::sync::Arc<std::sync::Mutex<bool>> {
    type Locks = Vec<(PathBuf, std::sync::Arc<std::sync::Mutex<bool>>)>;
    static LOCKS: std::sync::Mutex<Locks> = std::sync::Mutex::new(Vec::new());
    let mut g = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, l)) = g.iter().find(|(p, _)| p == path) {
        return l.clone();
    }
    let l = std::sync::Arc::new(std::sync::Mutex::new(false));
    g.push((path.to_path_buf(), l.clone()));
    l
}

/// The GUID in a PDB file's PDB info stream (the stream `pdbconv` takes the GUID from), as
/// the symbol server path spells it; `None` for a file that is not an MSF PDB.
pub fn pdb_file_guid(pdb: &[u8]) -> Option<String> {
    let msf = super::msf::Msf::open(pdb).ok()?;
    let info = msf.paged(1)?;
    let at = info.m(12);
    let mut g = [0u8; 16];
    for (i, x) in g.iter_mut().enumerate() {
        *x = info.u8(info.m(at + i as u64)).ok()?;
    }
    Some(super::guid_string(&g))
}

/// Kernel PDBs (8-13 MB on current Windows, 2-9 MB on older ones): their ranged download sends
/// parts covering 12.5 MiB with the size probe.
fn is_kernel_pdb(pdb_name: &str) -> bool {
    matches!(pdb_name.to_ascii_lowercase().as_str(), "ntkrnlmp.pdb" | "ntoskrnl.pdb" | "ntkrnlpa.pdb" | "ntkrpamp.pdb")
}

/// How a PDB is downloaded (see [`crate::util::download::download_ranged_to`]): a kernel PDB
/// in parallel parts of 800 KiB, sixteen of them sent with the size probe (a 12.4 MB
/// `ntkrnlmp.pdb`: 0.6-0.8 s instead of 1.1-1.9 s as one request, measured interleaved; 8
/// parts of 1.5 MiB: 0.7-1.0 s); others in parts of 1 MiB, two with the probe (a small driver
/// PDB is then one part).
fn range_plan(pdb_name: &str) -> crate::util::download::RangePlan {
    use crate::util::download::RangePlan;
    // `RSVOL_PDB_RANGES=<first wave>,<part KiB>,<max parts>` (measurements)
    if let Some(v) = std::env::var("RSVOL_PDB_RANGES").ok().map(|v| v.split(',').filter_map(|x| x.parse::<u64>().ok()).collect::<Vec<_>>())
        && let [w, kib, m] = v[..]
    {
        return RangePlan { first_wave: w as usize, part: kib << 10, max_parts: m as usize };
    }
    if is_kernel_pdb(pdb_name) {
        RangePlan { first_wave: 16, part: 800 << 10, max_parts: 24 }
    } else {
        RangePlan { first_wave: 2, part: 1 << 20, max_parts: 12 }
    }
}

fn fetch_pdb_in(dir: &Path, reuse: bool, pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<PathBuf> {
    if offline {
        return Err(Error::Unsatisfied(format!(
            "offline mode: not downloading {pdb_name} {}{age}",
            guid.to_uppercase()
        )));
    }
    let mut last_err = None;
    for url in symbol_server_urls(pdb_name, guid, age) {
        let path = pdb_cache_path(dir, &url);
        let lock = fetch_lock(&path);
        let mut here = lock.lock().unwrap_or_else(|e| e.into_inner());
        if (reuse || *here) && std::fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() > 0) {
            return Ok(path);
        }
        // the ranged parts must add up to the PDB asked for (a `.pd_` is a CAB: not checked)
        let want = guid.to_uppercase();
        let verify = |p: &Path| {
            !url.ends_with(".pdb")
                || std::fs::File::open(p).ok().and_then(|f| crate::util::mmap::Mmap::map(&f).ok()).and_then(|m| pdb_file_guid(m.as_slice())).is_some_and(|g| g == want)
        };
        let got = {
            let _t = crate::util::trace::span("pdb download");
            crate::util::download::download_ranged_to(&url, &path, range_plan(pdb_name), &verify)
        };
        match got {
            Ok(()) if std::fs::metadata(&path).is_ok_and(|m| m.len() > 0) => {
                *here = true;
                return Ok(path);
            }
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
                last_err = Some(Error::Msg(format!("empty response from {url}")));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::msg("PDB file could not be retrieved from the internet")))
}

/// [`fetch_pdb`], returning the file's contents.
pub fn download_pdb(pdb_name: &str, guid: &str, age: u32, offline: bool) -> Result<Vec<u8>> {
    Ok(std::fs::read(fetch_pdb(pdb_name, guid, age, offline)?)?)
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
    download_and_convert_with(pdb_name, guid, age, dirs, offline, false).map(|(p, j, _)| (p, j))
}

/// [`download_and_convert`]; with `defer`, the table is not compressed and written here: the
/// returned [`IsfWrite`] does it later (after the output, in a helper process, see
/// `store::finish_deferred`), and the file stays under its temporary name meanwhile.
pub fn download_and_convert_with(pdb_name: &str, guid: &str, age: u32, dirs: &[PathBuf], offline: bool, defer: bool) -> Result<(PathBuf, Vec<u8>, Option<IsfWrite>)> {
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
    let res = (|| -> Result<(Vec<u8>, Option<IsfWrite>)> {
        let c = match take_ahead(pdb_name, guid, age) {
            Some(c) => c,
            None => convert(&fetch_pdb(pdb_name, guid, age, false)?, pdb_name)?,
        };
        let job = IsfWrite { pdb: c.pdb, pdb_name: pdb_name.to_string(), datetime: c.datetime, tmp: tmp.clone(), path: path.clone() };
        if defer {
            return Ok((c.json, Some(job)));
        }
        write_isf(&job.tmp, &job.path, &c.json)?;
        Ok((c.json, None))
    })();
    match res {
        Ok((json, job)) => Ok((path, json, job)),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A converted table: the PDB, the producer datetime written into the JSON, the JSON.
struct Converted {
    pdb: PathBuf,
    datetime: String,
    json: Vec<u8>,
}

/// python `PdbReader(ctx, url, pdb_name).get_json()` of the PDB file `pdb`.
fn convert(pdb: &Path, pdb_name: &str) -> Result<Converted> {
    let file = std::fs::File::open(pdb)?;
    let map = crate::util::mmap::Mmap::map(&file)?;
    let datetime = super::python_now_isoformat();
    let _t = crate::util::trace::span("pdb conversion");
    let json = super::pdb_to_isf_bytes(map.as_slice(), Some(pdb_name), &datetime)?;
    Ok(Converted { pdb: pdb.to_path_buf(), datetime, json })
}

/// Compress `json` into `tmp` and rename it to `path`; the (size, mtime) of the file.
fn write_isf(tmp: &Path, path: &Path, json: &[u8]) -> Result<(u64, i128)> {
    let xz = {
        let _t = crate::util::trace::span("pdb isf xz compression");
        xz_isf(json)
    };
    std::fs::write(tmp, &xz)?;
    let stamp = crate::util::paths::file_stamp(tmp).ok_or_else(|| Error::msg("cannot stat the converted table"))?;
    std::fs::rename(tmp, path)?;
    Ok(stamp)
}

type Ahead = ((String, String, u32), std::thread::JoinHandle<Option<Converted>>);

/// Conversions started by [`convert_ahead`].
static AHEAD: std::sync::Mutex<Vec<Ahead>> = std::sync::Mutex::new(Vec::new());

/// Start converting the PDB of `pdb_name` + `guid` + `age` on another thread, in memory only,
/// for a lookup that is likely to convert it next: the conversion that follows uses the result
/// ([`download_and_convert_with`]); nothing is written otherwise. `download`: fetch the PDB
/// first if python's cache lacks it (the speculative kernel lookup, once no ISF was found for
/// it: python downloads the same file unless a later KDBG hit changes the kernel); else only
/// a PDB in the cache is converted (e.g. while the identifier index is built).
pub fn convert_ahead(pdb_name: &str, guid: &str, age: u32, download: bool) {
    if check_name(pdb_name).is_err() {
        return;
    }
    let key = (pdb_name.to_string(), guid.to_uppercase(), age);
    let mut g = AHEAD.lock().unwrap_or_else(|e| e.into_inner());
    if g.iter().any(|(k, _)| *k == key) {
        return;
    }
    let pdb = if download {
        None
    } else {
        let (dir, reuse) = python_cache();
        // (a PDB being downloaded right now is not waited for: the lookup waits for it later)
        let cached = symbol_server_urls(pdb_name, guid, age).iter().map(|u| pdb_cache_path(&dir, u)).find(|p| {
            let Ok(here) = fetch_lock(p).try_lock().map(|g| *g) else { return false };
            (reuse || here) && std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.len() > 0)
        });
        match cached {
            Some(p) => Some(p),
            None => return,
        }
    };
    let (name, guid) = (pdb_name.to_string(), guid.to_string());
    let job = move || {
        let pdb = match pdb {
            Some(p) => p,
            None => {
                let _t = crate::util::trace::span("pdb download (ahead)");
                fetch_pdb(&name, &guid, age, false).ok()?
            }
        };
        convert(&pdb, &name).ok()
    };
    if let Ok(h) = std::thread::Builder::new().name("rsvol-pdbconv".into()).spawn(job) {
        g.push((key, h));
    }
}

/// Wait for the [`convert_ahead`] work nothing used (a download in progress must not be cut
/// off by the exit: no partial files are left in python's cache). `main` calls this after the
/// output (via `store::finish_deferred`).
pub fn finish_ahead() {
    let left = std::mem::take(&mut *AHEAD.lock().unwrap_or_else(|e| e.into_inner()));
    for (_, h) in left {
        let _ = h.join();
    }
}

/// The result of a [`convert_ahead`] of this PDB (waited for).
fn take_ahead(pdb_name: &str, guid: &str, age: u32) -> Option<Converted> {
    let key = (pdb_name.to_string(), guid.to_uppercase(), age);
    let h = {
        let mut g = AHEAD.lock().unwrap_or_else(|e| e.into_inner());
        let i = g.iter().position(|(k, _)| *k == key)?;
        g.swap_remove(i).1
    };
    h.join().ok().flatten()
}

/// A converted table whose `.json.xz` is still to be written ([`download_and_convert_with`]
/// with `defer`): the PDB and the producer datetime of the JSON the run uses, so the file
/// written later holds exactly that JSON; the temporary file and the final path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsfWrite {
    pub pdb: PathBuf,
    pub pdb_name: String,
    pub datetime: String,
    pub tmp: PathBuf,
    pub path: PathBuf,
}

impl IsfWrite {
    /// One line (a helper process's environment value): the fields hex-encoded.
    pub fn encode(&self) -> String {
        use crate::util::paths::hex;
        let b = |p: &Path| hex(p.as_os_str().as_encoded_bytes());
        format!("{}:{}:{}:{}:{}", b(&self.pdb), hex(self.pdb_name.as_bytes()), hex(self.datetime.as_bytes()), b(&self.tmp), b(&self.path))
    }

    pub fn decode(s: &str) -> Option<IsfWrite> {
        use std::os::unix::ffi::OsStringExt;
        let unhex = |h: &str| -> Option<Vec<u8>> {
            (h.len() % 2 == 0).then_some(())?;
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
        };
        let path = |h: &str| Some(PathBuf::from(std::ffi::OsString::from_vec(unhex(h)?)));
        let f: Vec<&str> = s.split(':').collect();
        let [pdb, name, dt, tmp, out] = f.as_slice() else { return None };
        Some(IsfWrite {
            pdb: path(pdb)?,
            pdb_name: String::from_utf8(unhex(name)?).ok()?,
            datetime: String::from_utf8(unhex(dt)?).ok()?,
            tmp: path(tmp)?,
            path: path(out)?,
        })
    }

    /// Convert the PDB again (the same JSON: same datetime), compress it into the temporary
    /// file and rename that into place. Returns the JSON and the (size, mtime) of the file
    /// written (`None` on failure: the temporary file is removed, nothing else is left).
    pub fn run(&self) -> Option<(Vec<u8>, (u64, i128))> {
        let r = (|| -> Result<(Vec<u8>, (u64, i128))> {
            let file = std::fs::File::open(&self.pdb)?;
            let map = crate::util::mmap::Mmap::map(&file)?;
            let json = super::pdb_to_isf_bytes(map.as_slice(), Some(&self.pdb_name), &self.datetime)?;
            drop(map);
            let stamp = write_isf(&self.tmp, &self.path, &json)?;
            Ok((json, stamp))
        })();
        if r.is_err() {
            let _ = std::fs::remove_file(&self.tmp);
        }
        r.ok()
    }

    /// Compress `json` (this job's JSON, still in memory) into place.
    pub fn run_with(&self, json: &[u8]) -> bool {
        let ok = write_isf(&self.tmp, &self.path, json).is_ok();
        if !ok {
            let _ = std::fs::remove_file(&self.tmp);
        }
        ok
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

    /// A PDB in python's cache (python's file name for the URL) is used without a download.
    #[test]
    fn pdb_kept_in_python_cache() {
        // python: hashlib.sha512(bytes(url, "raw_unicode_escape")).hexdigest()
        let url = &symbol_server_urls("ntkrnlmp.pdb", "8e3373d6124e747f0e72ef8e02e676b3", 1)[0];
        let name = pdb_cache_path(Path::new("/c"), url);
        assert_eq!(
            name.to_str().unwrap(),
            "/c/data_4b0f7e7467e414c27795057e12998e845eea045d8863f194908ce99896253624284202aade8d0f24f4b61f1e1e5c2058bcc9bbc4fb9c9f0efb86176c5e305f11.cache"
        );
        let dir = std::env::temp_dir().join(format!("rsvol-pdbcache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // an unreachable symbol server would fail every download: the cached file is used
        let p = pdb_cache_path(&dir, &symbol_server_urls("k.pdb", "AB", 2)[0]);
        std::fs::write(&p, b"Microsoft C/C++ MSF 7.00\r\n").unwrap();
        assert_eq!(fetch_pdb_in(&dir, true, "k.pdb", "ab", 2, false).unwrap(), p);
        assert!(fetch_pdb_in(&dir, true, "k.pdb", "ab", 2, true).is_err(), "offline: never");
        let _ = std::fs::remove_dir_all(&dir);
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
