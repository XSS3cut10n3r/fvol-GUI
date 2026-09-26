//! python `ResourceAccessor.open` (framework/layers/resources.py) for the files layers read:
//! the image (`-f` / `--single-location`) and swap files. (VMware metadata files never end in
//! a compression extension: the stacker downloads them directly.)
//!
//! A remote location is downloaded once into the rsvol cache (see [`super::download`]). A
//! compressed one is decompressed: python wraps the file in `lzma.LZMAFile`, `bz2.BZ2File` or
//! `gzip.GzipFile` and decompresses on every read (a backwards seek starts over from the
//! beginning of the file); rsvol decompresses once, in parallel where the format allows,
//! into `<rsvol cache>/decompressed/` and memory-maps the result, so repeated runs pay
//! nothing. What python prints (layer names, the location in configurations) is unchanged:
//! the location stays the compressed file's.
//!
//! Detection is python's without the optional `magic` module (not part of volatility3's
//! requirements, nor of the reference installation): the extensions at the end of the URL
//! path, outermost last, so `x.raw.gz` is gunzipped and `x.gz.xz` un-xz'd then gunzipped. A
//! compressed file without such an extension is read as it is, as python does.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

use crate::error::{Error, Result};
use crate::util::paths;
use std::path::{Path, PathBuf};

/// A decompressor python's ResourceAccessor applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// `.xz` (`lzma.LZMAFile`)
    Xz,
    /// `.bz2` (`bz2.BZ2File`)
    Bzip2,
    /// `.gz` (`gzip.GzipFile`)
    Gzip,
}

impl Codec {
    fn name(self) -> &'static str {
        match self {
            Codec::Xz => "xz",
            Codec::Bzip2 => "bz2",
            Codec::Gzip => "gz",
        }
    }
}

/// python `urllib.parse.urlparse(url).path` (for the URLs volatility3 builds: `file:` URLs of
/// absolute paths and http(s)/ftp URLs; a string without a scheme is a path).
pub fn url_path(url: &str) -> &str {
    let scheme_end = url.find(':').filter(|&i| {
        let s = &url.as_bytes()[..i];
        i > 0 && s[0].is_ascii_alphabetic() && s.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    });
    let (scheme, mut rest) = match scheme_end {
        Some(i) => (&url[..i], &url[i + 1..]),
        None => ("", url),
    };
    if let Some(r) = rest.strip_prefix("//") {
        rest = &r[r.find(['/', '?', '#']).unwrap_or(r.len())..];
    }
    rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    // `;params` of the last segment, for the schemes urllib splits them off
    if matches!(scheme.to_ascii_lowercase().as_str(), "" | "http" | "https" | "ftp" | "sftp")
        && let Some(semi) = rest.rfind(';')
        && !rest[semi..].contains('/')
    {
        rest = &rest[..semi];
    }
    rest
}

/// The decompressors python applies to `url`, in order (outermost first): python's
/// extension loop over the URL path (`.xz`, `.bz2`, `.gz`, case-sensitive, repeated).
pub fn compression_chain(url: &str) -> Vec<Codec> {
    let mut path = url_path(url);
    let mut chain = Vec::new();
    loop {
        let (stem, ext) = match path.rfind('.') {
            Some(i) => (&path[..i], &path[i + 1..]),
            None => ("", path),
        };
        let c = match ext {
            "xz" => Codec::Xz,
            "bz2" => Codec::Bzip2,
            "gz" => Codec::Gzip,
            _ => return chain,
        };
        chain.push(c);
        path = stem;
    }
}

/// The local file with the bytes python reads for location `url`: `local` (the path of a
/// `file:` URL, if the caller has it) or the download of a remote URL, decompressed into the
/// cache when the URL names a compressed file.
pub fn open(url: &str, local: Option<&Path>, offline: bool) -> Result<PathBuf> {
    open_in(&paths::rsvol_cache_dir(), url, local, offline)
}

/// [`open`] with the rsvol cache directory `cache`.
fn open_in(cache: &Path, url: &str, local: Option<&Path>, offline: bool) -> Result<PathBuf> {
    let file = match local {
        Some(p) => p.to_path_buf(),
        None if super::download::is_remote(url) => super::download::fetch(url, offline)?,
        None => match url.strip_prefix("file://") {
            Some(p) => PathBuf::from(paths::unquote(p)),
            None => PathBuf::from(url),
        },
    };
    let chain = compression_chain(url);
    if chain.is_empty() {
        return Ok(file);
    }
    let _t = crate::util::trace::span("decompressing the image");
    decompressed(&cache.join(CACHE_SUBDIR), &file, url, &chain)
}

/// Bump when the decompressed files change meaning.
const CACHE_VERSION: u32 = 1;

/// Directory of the decompressed files (removed by `--clear-cache`).
pub const CACHE_SUBDIR: &str = "decompressed";

/// The decompressed contents of `src` (python's view of location `url`), from the cache or
/// decompressed into it now. Cache entries are keyed by the location, the canonical path,
/// size and modification time of `src`, and the codecs; the full key is stored next to the
/// data and compared, so a stale or colliding entry is a miss. A new entry replaces the
/// older ones of the same location.
fn decompressed(dir: &Path, src: &Path, url: &str, chain: &[Codec]) -> Result<PathBuf> {
    let canon = paths::canonicalize(src).map_err(|e| Error::Msg(format!("{}: {e}", src.display())))?;
    let (size, mtime) = paths::file_stamp(&canon).ok_or_else(|| Error::Msg(format!("{}: cannot stat", canon.display())))?;
    let codecs: Vec<&str> = chain.iter().map(|c| c.name()).collect();
    let key = format!(
        "version={CACHE_VERSION}\nlocation={url}\npath={}\nsize={size}\nmtime={mtime}\ncodecs={}\n",
        canon.display(),
        codecs.join(",")
    );
    let prefix = format!("{:016x}-", crate::layers::scancache::key_hash(url.as_bytes()));
    let stem = format!("{prefix}{:016x}", crate::layers::scancache::key_hash(key.as_bytes()));
    let data = dir.join(format!("{stem}.img"));
    let keyf = dir.join(format!("{stem}.key"));
    if let Ok(k) = std::fs::read_to_string(&keyf)
        && let Some(len) = k.strip_prefix(&key).and_then(|r| r.strip_prefix("length=")).and_then(|r| r.trim_end().parse::<u64>().ok())
        && std::fs::metadata(&data).is_ok_and(|m| m.is_file() && m.len() == len)
    {
        return Ok(data);
    }
    let where_ = |e: Error| Error::Msg(format!("{e} (decompressing into {}; RSVOL_CACHE selects another directory)", dir.display()));
    std::fs::create_dir_all(dir).map_err(|e| where_(Error::Msg(format!("cannot create the directory: {e}"))))?;
    remove_stale(dir, &prefix);
    let pid = std::process::id();
    let tmp = dir.join(format!("{stem}.img.tmp{pid}"));
    // outputs written so far (the input of the next stage last)
    let mut written: Vec<PathBuf> = Vec::new();
    let res = (|| -> Result<u64> {
        let mut len = 0;
        for (i, &codec) in chain.iter().enumerate() {
            let out = if i + 1 == chain.len() { tmp.clone() } else { dir.join(format!("{stem}.stage{i}.tmp{pid}")) };
            let input = written.last().cloned().unwrap_or_else(|| src.to_path_buf());
            written.push(out.clone());
            len = decompress_file(codec, &input, &out)?;
            if i > 0 {
                // the previous stage's output was this stage's input
                let _ = std::fs::remove_file(&input);
            }
        }
        Ok(len)
    })();
    let len = match res {
        Ok(len) => len,
        Err(e) => {
            for p in written {
                let _ = std::fs::remove_file(p);
            }
            return Err(where_(e));
        }
    };
    std::fs::rename(&tmp, &data).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::Msg(format!("cannot write {}: {e}", data.display()))
    })?;
    // the key last: an entry without one is a miss
    let _ = paths::write_atomic(&keyf, format!("{key}length={len}\n").as_bytes());
    Ok(data)
}

/// Removes from `dir` the entries of an earlier version of the location whose names start
/// with `prefix` (its source file changed), and temporary files of processes that are gone.
fn remove_stale(dir: &Path, prefix: &str) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(n) = name.to_str() else { continue };
        let stale = match n.rsplit_once(".tmp") {
            // "<stem>.img.tmp<pid>", "<stem>.stage<i>.tmp<pid>": the writer died
            Some((_, pid)) => pid.parse::<u32>().is_ok_and(|p| p != std::process::id() && !Path::new(&format!("/proc/{p}")).exists()),
            None => n.starts_with(prefix),
        };
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Decompresses file `src` into a new file `dst`; returns the decompressed size.
fn decompress_file(codec: Codec, src: &Path, dst: &Path) -> Result<u64> {
    decompress_file_with(codec, src, dst, crate::codecs::xz::FILE_BUF_MAX)
}

/// [`decompress_file`]; xz blocks bigger than `xz_buf_max` are decoded into a mapping.
fn decompress_file_with(codec: Codec, src: &Path, dst: &Path, xz_buf_max: usize) -> Result<u64> {
    let io = |p: &Path, e: std::io::Error| Error::Msg(format!("{}: {e}", p.display()));
    let f = std::fs::File::open(src).map_err(|e| io(src, e))?;
    let map = crate::util::mmap::Mmap::map(&f).map_err(|e| io(src, e))?;
    map.advise(0, map.len(), crate::util::mmap::MADV_SEQUENTIAL);
    let input = map.as_slice();
    // readable too: big xz blocks are decoded into a shared mapping of the file
    let out = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(dst).map_err(|e| io(dst, e))?;
    let what = match codec {
        Codec::Xz => "xz",
        Codec::Bzip2 => "bzip2",
        Codec::Gzip => "gzip",
    };
    let fail = |e: Error| Error::Msg(format!("cannot decompress {} ({what}): {e}", src.display()));
    // python's BZ2File and LZMAFile (unlike GzipFile and bz2.decompress) fail on an empty file
    if input.is_empty() && codec != Codec::Gzip {
        return Err(fail(Error::Msg("Compressed file ended before the end-of-stream marker was reached".into())));
    }
    // python's LZMAFile reads both .xz and legacy .lzma data (FORMAT_AUTO: .xz by its magic)
    if codec == Codec::Xz && crate::codecs::xz::is_xz(input) {
        return crate::codecs::xz::decompress_to_file_with(input, &out, xz_buf_max).map_err(fail);
    }
    let mut sink = crate::codecs::sink::FileSink::new(out)?;
    let n = match codec {
        Codec::Gzip => crate::codecs::gzip::decompress_to(input, &mut sink),
        Codec::Bzip2 => crate::codecs::bzip2::decompress_to(input, &mut sink),
        Codec::Xz => crate::codecs::lzma::decompress_alone_to(input, &mut sink),
    }
    .map_err(fail)?;
    sink.finish()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decoder throughput without the file system: `RSVOL_DECOMP_BENCH=<file.gz|.bz2>`
    /// `cargo test --profile fast decomp_throughput -- --ignored --nocapture` (into a sink
    /// that drops the data).
    #[test]
    #[ignore]
    fn decomp_throughput() {
        struct Drop0(u64);
        impl crate::codecs::sink::Sink for Drop0 {
            fn flush(&mut self, buf: &mut Vec<u8>, from: usize, keep: usize) -> Result<()> {
                self.0 += (buf.len() - from) as u64;
                let n = buf.len();
                buf.copy_within(n - keep.min(n).., 0);
                buf.truncate(keep.min(n));
                Ok(())
            }
            fn position(&self) -> u64 {
                self.0
            }
            fn truncate(&mut self, len: u64) -> Result<()> {
                self.0 = len;
                Ok(())
            }
        }
        let p = PathBuf::from(std::env::var("RSVOL_DECOMP_BENCH").expect("RSVOL_DECOMP_BENCH"));
        let f = std::fs::File::open(&p).unwrap();
        let map = crate::util::mmap::Mmap::map(&f).unwrap();
        let data = map.as_slice();
        let t = std::time::Instant::now();
        let n = match compression_chain(&p.to_string_lossy()).first() {
            Some(Codec::Gzip) => crate::codecs::gzip::decompress_to(data, &mut Drop0(0)).unwrap(),
            Some(Codec::Bzip2) => crate::codecs::bzip2::decompress_to(data, &mut Drop0(0)).unwrap(),
            _ => panic!("not a .gz / .bz2 file"),
        };
        let s = t.elapsed().as_secs_f64();
        eprintln!("{}: {n} bytes in {s:.3}s = {:.0} MB/s", p.display(), n as f64 / s / 1e6);
    }

    #[test]
    fn python_url_paths_and_extensions() {
        assert_eq!(url_path("file:///a/b%20c/x.raw.gz"), "/a/b%20c/x.raw.gz");
        assert_eq!(url_path("http://h:8000/p/x.gz?q=1#f"), "/p/x.gz");
        assert_eq!(url_path("http://h/p/x.gz;type=a"), "/p/x.gz");
        assert_eq!(url_path("file:/a/x.xz"), "/a/x.xz");
        assert_eq!(url_path("/plain/x.bz2"), "/plain/x.bz2");
        assert_eq!(url_path("http://h"), "");
        use Codec::*;
        assert_eq!(compression_chain("file:///i/x.raw.gz"), vec![Gzip]);
        assert_eq!(compression_chain("file:///i/x.gz.bz2.xz"), vec![Xz, Bzip2, Gzip]);
        assert_eq!(compression_chain("http://h/x.lime.xz?raw=1"), vec![Xz]);
        assert!(compression_chain("file:///i/x.raw").is_empty());
        assert!(compression_chain("file:///i/x.GZ").is_empty());
        assert!(compression_chain("file:///i.gz/x").is_empty());
        assert!(compression_chain("http://h.gz").is_empty());
        assert!(compression_chain("file:///i/xgz").is_empty());
        // a bare "gz" name is python's `extension` too (no dot left to split on)
        assert_eq!(compression_chain("gz"), vec![Gzip]);
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rsvol-res-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Every codec (and a chain of them) decompresses into the cache once; the entry is
    /// reused while the source is unchanged and replaced when it changes.
    #[test]
    fn decompresses_once_into_the_cache() {
        let dir = scratch("cache");
        let cache = dir.join("cache");
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 29) as u8 ^ (i >> 12) as u8).collect();
        let gzopt = |level| crate::codecs::gzip_enc::GzipOptions::python(level, 0);
        let gz = crate::codecs::gzip_enc::gzip_compress(&data, &gzopt(1));
        let bz = crate::codecs::bzip2_enc::bzip2_compress(&data, 1);
        let xz = crate::codecs::xz_enc::xz_compress(&data, 1);
        let gzxz = crate::codecs::xz_enc::xz_compress(&gz, 0);
        let open = |url: &str, p: &Path| open_in(&cache, url, Some(p), false);
        for (name, bytes) in [("a.raw.gz", &gz), ("a.raw.bz2", &bz), ("a.raw.xz", &xz), ("a.raw.gz.xz", &gzxz)] {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            let url = paths::path_to_file_uri(&p);
            let out = open(&url, &p).unwrap();
            assert_eq!(std::fs::read(&out).unwrap(), data, "{name}");
            let again = open(&url, &p).unwrap();
            assert_eq!(out, again);
        }
        // a changed source gets a new entry and the old one is removed
        let p = dir.join("a.raw.gz");
        let url = paths::path_to_file_uri(&p);
        let old = open(&url, &p).unwrap();
        std::fs::write(&p, crate::codecs::gzip_enc::gzip_compress(&data[..1000], &gzopt(6))).unwrap();
        let new = open(&url, &p).unwrap();
        assert_ne!(old, new);
        assert!(!old.exists());
        assert_eq!(std::fs::read(&new).unwrap(), &data[..1000]);
        // legacy .lzma data in a .xz file (python's LZMAFile: FORMAT_AUTO)
        let p = dir.join("l.raw.xz");
        std::fs::write(&p, include_bytes!("../codecs/testdata/text4.d4k.lzma")).unwrap();
        let out = open(&paths::path_to_file_uri(&p), &p).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), include_bytes!("../codecs/testdata/text.json").repeat(4));
        // not compressed: the file itself; corrupt: an error and nothing left behind
        let raw = dir.join("a.raw");
        std::fs::write(&raw, b"x").unwrap();
        assert_eq!(open(&paths::path_to_file_uri(&raw), &raw).unwrap(), raw);
        let bad = dir.join("b.raw.xz");
        std::fs::write(&bad, b"not xz at all").unwrap();
        assert!(open(&paths::path_to_file_uri(&bad), &bad).is_err());
        // empty: python's GzipFile reads nothing, BZ2File and LZMAFile raise EOFError
        for (name, ok) in [("e.raw.gz", true), ("e.raw.bz2", false), ("e.raw.xz", false)] {
            let p = dir.join(name);
            std::fs::write(&p, b"").unwrap();
            let r = open(&paths::path_to_file_uri(&p), &p);
            assert_eq!(r.is_ok(), ok, "{name}");
            if let Ok(out) = r {
                assert_eq!(std::fs::metadata(out).unwrap().len(), 0);
            }
        }
        let left: Vec<_> = std::fs::read_dir(cache.join(CACHE_SUBDIR)).unwrap().flatten().map(|e| e.file_name()).collect();
        assert!(left.iter().all(|n| !n.to_string_lossy().contains(".tmp")), "{left:?}");
        // stale entries: an older version of a location, temporary files of dead writers
        let d = dir.join("stale");
        std::fs::create_dir_all(&d).unwrap();
        let me = std::process::id();
        for n in ["aa-1.img", "aa-1.key", "bb-2.img", "bb-2.img.tmp4000000000", "cc.stage0.tmp4000000001", "cc.tmp1x"] {
            std::fs::write(d.join(n), b"").unwrap();
        }
        std::fs::write(d.join(format!("bb-3.img.tmp{me}")), b"").unwrap();
        remove_stale(&d, "aa-");
        let mut left: Vec<String> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, ["bb-2.img".to_string(), format!("bb-3.img.tmp{me}"), "cc.tmp1x".to_string()]);
        // xz blocks decoded into a mapping of the output file (blocks over 64 MiB)
        let (src, dst) = (dir.join("a.raw.xz"), dir.join("mapped.out"));
        assert_eq!(decompress_file_with(Codec::Xz, &src, &dst, 0).unwrap(), data.len() as u64);
        assert_eq!(std::fs::read(&dst).unwrap(), data);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
