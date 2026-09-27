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

// ---------------------------------------------------------------------------------------------
// Parallel ranged download
// ---------------------------------------------------------------------------------------------

/// How [`download_ranged_to`] splits a download into HTTP `Range` requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangePlan {
    /// Requests of `part` bytes from offset 0 sent together with the size probe, before the
    /// size is known (a request past the end is answered 416 and costs one round trip).
    pub first_wave: usize,
    /// Bytes per request.
    pub part: u64,
    /// Most requests of one download (the parts after the first wave grow to fit).
    pub max_parts: usize,
}

/// Downloads `url` into `dest` (atomically, like [`download_to`]) as parallel HTTP `Range`
/// requests, each on its own connection: a single transfer is limited by one TCP window (the
/// symbol server's blob store serves ~10-20 MB/s per connection, after a 200 ms TLS + first
/// byte round trip), so an 8-13 MB kernel PDB comes down in about half the time. The redirect
/// is resolved first (without following it: its target is where the ranges go), then a 1-byte
/// size probe and the first `plan.first_wave` parts are sent at once, then the rest.
///
/// Every part must be a `206` whose `Content-Range` is exactly the requested range of the same
/// total size and whose `ETag` matches the probe's; the assembled file must pass `verify`.
/// Anything else (a server without range support, a resource that changed, a failed or short
/// part, a certificate problem) falls back to [`download_to`]: one request, python's way. The
/// bytes are the same either way. `RSVOL_RANGED_DOWNLOAD=0` always makes one request.
pub fn download_ranged_to(url: &str, dest: &Path, plan: RangePlan, verify: &dyn Fn(&Path) -> bool) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let on = std::env::var_os("RSVOL_RANGED_DOWNLOAD").is_none_or(|v| v != "0");
    if on && plan.part > 0 && plan.max_parts > 1 {
        let _t = crate::util::trace::span("download: ranged");
        match ranged(url, dest, plan, verify) {
            Ok(()) => return Ok(()),
            Err(why) => crate::util::trace::note(|| format!("download: ranged download of {url} not used ({why}); one request")),
        }
    }
    let _t = crate::util::trace::span("download: one request");
    download_to(url, dest)
}

/// One curl process fetching `range` of `url`: the body on its stdout, the response headers
/// into `hdr`.
fn spawn_range(url: &str, range: (u64, u64), hdr: &Path) -> std::io::Result<std::process::Child> {
    Command::new("curl")
        .args(["--silent", "--globoff", "--connect-timeout", "30", "--range", &format!("{}-{}", range.0, range.1)])
        .arg("--dump-header")
        .arg(hdr)
        .args(["--output", "-", "--", url])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
}

/// A response: status, `Content-Range` (start, end, total; `None` for `*/total`), `ETag`,
/// `Location`.
#[derive(Debug, Default, PartialEq, Eq)]
struct Resp {
    status: u32,
    range: Option<(Option<(u64, u64)>, u64)>,
    etag: Option<String>,
    location: String,
}

/// Parses the last response of a `--dump-header` file.
fn parse_resp(headers: &str) -> Resp {
    let block = headers.split("\r\n\r\n").filter(|b| !b.trim().is_empty()).last().unwrap_or("");
    let mut lines = block.lines();
    // "HTTP/1.1 206 Partial Content", "HTTP/2 206"
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut r = Resp { status, ..Resp::default() };
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-range") {
            let Some(spec) = v.strip_prefix("bytes ") else { continue };
            let Some((span, total)) = spec.split_once('/') else { continue };
            let Ok(total) = total.trim().parse::<u64>() else { continue };
            let span = if span == "*" {
                None
            } else {
                let Some((a, b)) = span.split_once('-') else { continue };
                let (Ok(a), Ok(b)) = (a.parse::<u64>(), b.parse::<u64>()) else { continue };
                Some((a, b))
            };
            r.range = Some((span, total));
        } else if k.eq_ignore_ascii_case("etag") {
            r.etag = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("location") {
            r.location = v.to_string();
        }
    }
    r
}

/// The absolute URL of redirect target `loc` from `base` (absolute, or host-relative).
fn redirect_target(base: &str, loc: &str) -> Option<String> {
    if is_remote(loc) {
        return Some(loc.to_string());
    }
    let rest = loc.strip_prefix('/')?;
    let scheme_end = base.find("://")? + 3;
    let host_end = base[scheme_end..].find('/').map_or(base.len(), |i| scheme_end + i);
    Some(format!("{}/{rest}", &base[..host_end]))
}

/// The temporary files and curl processes of a ranged download: on drop, the processes still
/// running are killed and reaped, their readers joined, the files removed.
struct Ranged {
    files: Vec<PathBuf>,
    children: Vec<std::process::Child>,
    readers: Vec<Option<std::thread::JoinHandle<u64>>>,
}

impl Drop for Ranged {
    fn drop(&mut self) {
        for c in self.children.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for r in self.readers.drain(..).flatten() {
            let _ = r.join();
        }
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// A request in flight: its range, header file, and indexes of its process and reader.
struct Sent {
    range: (u64, u64),
    hdr: PathBuf,
    k: usize,
}

impl Ranged {
    /// Send a request for `range` of `url`; its body is written into `out` from offset
    /// `range.0`, at most `limit` bytes (the rest is read and dropped).
    fn send(&mut self, url: &str, range: (u64, u64), out: &std::sync::Arc<std::fs::File>, limit: u64, hdr: PathBuf) -> std::result::Result<Sent, String> {
        use std::io::Read;
        use std::os::unix::fs::FileExt;
        self.files.push(hdr.clone());
        let mut c = spawn_range(url, range, &hdr).map_err(|e| format!("cannot run curl: {e}"))?;
        let mut body = c.stdout.take().ok_or("no pipe")?;
        let out = out.clone();
        let at = range.0;
        let reader = std::thread::Builder::new()
            .name("rsvol-dl".into())
            .spawn(move || {
                let mut buf = vec![0u8; 256 << 10];
                let mut n = 0u64;
                loop {
                    let k = match body.read(&mut buf) {
                        Ok(0) | Err(_) => return n,
                        Ok(k) => k,
                    };
                    let keep = (k as u64).min(limit.saturating_sub(n)) as usize;
                    if keep > 0 && out.write_all_at(&buf[..keep], at + n).is_err() {
                        return u64::MAX;
                    }
                    n += k as u64;
                }
            })
            .map_err(|e| e.to_string())?;
        self.children.push(c);
        self.readers.push(Some(reader));
        Ok(Sent { range, hdr, k: self.children.len() - 1 })
    }

    /// Wait for request `s`: its response (status 0 when curl failed: no connection, TLS
    /// error...) and the number of body bytes received.
    fn finish(&mut self, s: &Sent) -> (Resp, u64) {
        let n = self.readers[s.k].take().map_or(u64::MAX, |h| h.join().unwrap_or(u64::MAX));
        match self.children[s.k].wait() {
            Ok(st) if st.success() => (parse_resp(&std::fs::read_to_string(&s.hdr).unwrap_or_default()), n),
            _ => (Resp::default(), n),
        }
    }
}

/// The ranged download (see [`download_ranged_to`]); `Err(reason)` = use one request instead.
fn ranged(url: &str, dest: &Path, plan: RangePlan, verify: &dyn Fn(&Path) -> bool) -> std::result::Result<(), String> {
    let t0 = std::time::Instant::now();
    let ms = || t0.elapsed().as_secs_f64() * 1e3;
    let pid = std::process::id();
    let name = |s: &str| dest.with_extension(format!("rng{pid}.{s}"));
    // the parts go straight into the file at their offsets; a size probe's body (one byte, or
    // everything from a server without range support) into a file of its own
    let tmp = dest.with_extension(format!("part{pid}"));
    let probe_out = name("p");
    let mut r = Ranged { files: vec![tmp.clone(), probe_out.clone()], children: Vec::new(), readers: Vec::new() };
    let io = |e: std::io::Error| e.to_string();
    let out = std::sync::Arc::new(std::fs::File::options().read(true).write(true).create(true).truncate(true).open(&tmp).map_err(io)?);
    let mut sent: Vec<Sent> = Vec::new();
    let mut here = url.to_string();
    let (probe, total) = {
        let mut hops = 0;
        loop {
            let pf = std::sync::Arc::new(std::fs::File::create(&probe_out).map_err(io)?);
            let p = r.send(&here, (0, 0), &pf, u64::MAX, name(&format!("h{hops}")))?;
            // after the first redirect the first parts go out with the probe (their target
            // is known, their offsets do not depend on the size)
            if hops == 1 && sent.is_empty() {
                for i in 0..plan.first_wave.min(plan.max_parts) as u64 {
                    let range = (i * plan.part, (i + 1) * plan.part - 1);
                    sent.push(r.send(&here, range, &out, plan.part, name(&format!("{i}")))?);
                }
            }
            let (resp, n) = r.finish(&p);
            match resp.status {
                301 | 302 | 303 | 307 | 308 if sent.is_empty() && hops < 8 => {
                    here = redirect_target(&here, &resp.location).ok_or("redirect without a usable Location")?;
                    hops += 1;
                    crate::util::trace::note(|| format!("download: redirect resolved at {:.1} ms", ms()));
                }
                // no range support: this one request was the whole download
                200 => {
                    drop(pf);
                    if n == 0 || n == u64::MAX || !verify(&probe_out) {
                        return Err("200 answer rejected".into());
                    }
                    std::fs::rename(&probe_out, dest).map_err(io)?;
                    return Ok(());
                }
                206 => match resp.range {
                    Some((Some((0, 0)), total)) if total > 0 && n == 1 => {
                        crate::util::trace::note(|| format!("download: size {total} known at {:.1} ms", ms()));
                        break (resp, total);
                    }
                    _ => return Err(format!("probe: unexpected Content-Range {:?}", resp.range)),
                },
                s => return Err(format!("probe: status {s}")),
            }
        }
    };
    // the rest: parts of about `plan.part` bytes, within `plan.max_parts`
    let covered = sent.len() as u64 * plan.part;
    if covered < total {
        let rest = total - covered;
        let n = rest.div_ceil(plan.part).min(plan.max_parts.saturating_sub(sent.len()).max(1) as u64);
        let per = rest.div_ceil(n);
        let mut a = covered;
        while a < total {
            let range = (a, (a + per).min(total) - 1);
            sent.push(r.send(&here, range, &out, range.1 - range.0 + 1, name(&format!("{}", sent.len())))?);
            a = range.1 + 1;
        }
    }
    let mut failed = None;
    for s in &sent {
        let (resp, n) = r.finish(s);
        if failed.is_some() {
            continue;
        }
        if s.range.0 >= total {
            // past the end (a first-wave part of a small file): its body (an error text) was
            // written past the end, cut off below
            if resp.status != 416 {
                failed = Some(format!("part {:?} past the end: status {}", s.range, resp.status));
            }
            continue;
        }
        let want = (s.range.0, s.range.1.min(total - 1));
        if resp.status != 206 || resp.range != Some((Some(want), total)) || resp.etag != probe.etag || n != want.1 - want.0 + 1 {
            failed = Some(format!("part {want:?}: status {} range {:?} etag {:?} bytes {n}", resp.status, resp.range, resp.etag));
        }
    }
    crate::util::trace::note(|| format!("download: {} parts done at {:.1} ms", sent.len(), ms()));
    if let Some(f) = failed {
        return Err(f);
    }
    out.set_len(total).map_err(io)?;
    drop(out);
    let ok = {
        let _t = crate::util::trace::span("download: verify");
        verify(&tmp)
    };
    if !ok {
        return Err("assembled file rejected".into());
    }
    std::fs::rename(&tmp, dest).map_err(io)?;
    Ok(())
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

    #[test]
    fn parse_responses() {
        let h = "HTTP/1.1 302 Found\r\nLocation: x\r\n\r\nHTTP/1.1 206 Partial Content\r\nContent-Range: bytes 5-9/100\r\netag: \"a\"\r\n\r\n";
        assert_eq!(parse_resp(h), Resp { status: 206, range: Some((Some((5, 9)), 100)), etag: Some("\"a\"".into()), location: String::new() });
        let r = parse_resp("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */7\r\n\r\n");
        assert_eq!((r.status, r.range), (416, Some((None, 7))));
        assert_eq!(parse_resp("HTTP/2 302\r\nlocation: http://h/b\r\n\r\n").location, "http://h/b");
        assert_eq!(parse_resp("").status, 0);
        assert_eq!(redirect_target("https://a.b/c/d?x", "/e?f").as_deref(), Some("https://a.b/e?f"));
        assert_eq!(redirect_target("http://a.b", "/e").as_deref(), Some("http://a.b/e"));
        assert_eq!(redirect_target("http://a.b/c", "https://x/y").as_deref(), Some("https://x/y"));
        assert_eq!(redirect_target("http://a.b/c", "rel"), None);
    }

    /// How the test server answers.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        /// `/r` redirects to `/blob`, which honours ranges
        Ranges,
        /// no range support (always 200 with the whole body)
        NoRanges,
        /// the second and later ranged requests get a wrong Content-Range
        BadRange,
        /// every response has another ETag (the resource "changes")
        NewEtag,
    }

    /// A tiny HTTP/1.1 server (one thread per connection, `Connection: close`) serving `data`;
    /// returns its port and a counter of (all requests, requests without a Range header).
    fn serve(data: Vec<u8>, mode: Mode) -> (u16, std::sync::Arc<[std::sync::atomic::AtomicUsize; 2]>) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let data = std::sync::Arc::new(data);
        let count = std::sync::Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let c2 = count.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let (data, count) = (data.clone(), c2.clone());
                std::thread::spawn(move || {
                    let mut req = Vec::new();
                    let mut b = [0u8; 1024];
                    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut b) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => req.extend_from_slice(&b[..n]),
                        }
                    }
                    let req = String::from_utf8_lossy(&req).into_owned();
                    let n = count[0].fetch_add(1, Ordering::SeqCst);
                    let path = req.split(' ').nth(1).unwrap_or("").to_string();
                    let range = req.lines().find_map(|l| l.strip_prefix("Range: bytes=")).and_then(|r| {
                        let (a, b) = r.trim().split_once('-')?;
                        Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))
                    });
                    if range.is_none() {
                        count[1].fetch_add(1, Ordering::SeqCst);
                    }
                    let etag = if mode == Mode::NewEtag { format!("\"v{n}\"") } else { "\"v1\"".into() };
                    let len = data.len() as u64;
                    let (head, body): (String, &[u8]) = if path == "/r" {
                        (format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/blob\r\nContent-Length: 0\r\n"), &[])
                    } else {
                        match range.filter(|_| mode != Mode::NoRanges) {
                            None => (format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nETag: {etag}\r\n"), &data[..]),
                            Some((a, _)) if a >= len => (format!("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{len}\r\nContent-Length: 0\r\n"), &[]),
                            Some((a, b)) => {
                                let b = b.min(len - 1);
                                let shown = if mode == Mode::BadRange && a > 0 { b + 1 } else { b };
                                (format!("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{shown}/{len}\r\nContent-Length: {}\r\nETag: {etag}\r\n", b - a + 1), &data[a as usize..=b as usize])
                            }
                        }
                    };
                    let _ = s.write_all(format!("{head}Connection: close\r\n\r\n").as_bytes());
                    let _ = s.write_all(body);
                });
            }
        });
        (port, count)
    }

    /// Ranged downloads reassemble the same bytes, from the first wave alone or with more
    /// parts; every unexpected answer falls back to one request (same bytes again), and no
    /// temporary file is left behind.
    #[test]
    fn ranged_download_same_bytes() {
        use std::sync::atomic::Ordering;
        let dir = std::env::temp_dir().join(format!("rsvol-rng-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plan = RangePlan { first_wave: 3, part: 100_000, max_parts: 8 };
        let data = |n: usize| -> Vec<u8> { (0..n).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect() };
        // (mode, size, verify ok, expected requests (all, without a Range header))
        let cases: &[(Mode, usize, bool, Option<(usize, usize)>)] = &[
            // redirect + probe + 3 first-wave parts (2 answered 416)
            (Mode::Ranges, 1, true, Some((5, 0))),
            (Mode::Ranges, 250_000, true, Some((5, 0))),
            // + 5 parts for the remaining 700 KB (8 at most)
            (Mode::Ranges, 1_000_000, true, Some((10, 0))),
            // the probe got everything
            (Mode::NoRanges, 300_000, true, None),
            (Mode::BadRange, 1_000_000, true, None),
            (Mode::NewEtag, 1_000_000, true, None),
            (Mode::Ranges, 1_000_000, false, None),
        ];
        for (k, &(mode, n, ok, want)) in cases.iter().enumerate() {
            let body = data(n);
            let (port, count) = serve(body.clone(), mode);
            let dest = dir.join(format!("d{k}.pdb"));
            download_ranged_to(&format!("http://127.0.0.1:{port}/r"), &dest, plan, &|_| ok).unwrap();
            assert!(std::fs::read(&dest).unwrap() == body, "case {k}: bytes differ");
            let got = (count[0].load(Ordering::SeqCst), count[1].load(Ordering::SeqCst));
            if let Some(w) = want {
                assert_eq!(got, w, "case {k}: requests");
            } else if mode != Mode::NoRanges {
                assert!(got.1 >= 1, "case {k}: fell back to one request ({got:?})");
            }
        }
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).filter(|n| !n.to_string_lossy().ends_with(".pdb")).collect();
        assert!(left.is_empty(), "temporary files left: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
