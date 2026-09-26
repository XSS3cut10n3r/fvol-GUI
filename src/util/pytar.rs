//! A tar writer producing exactly what python's `tarfile` module writes in its default
//! `PAX_FORMAT` (CPython 3.14 `tarfile.TarFile.addfile` / `TarInfo.tobuf` / `TarFile.close`),
//! for plugins that build tarballs (`linux.pagecache.RecoverFs`).
//!
//! Derived from the behaviour of CPython's `Lib/tarfile.py` (PSF License).
//!
//! What python does and we replicate:
//!   * every member whose `mtime` is a float (e.g. `time.time()`) gets a pax extended header
//!     (`././@PaxHeader`, type `x`) carrying `mtime=<repr(float)>`; the ustar header holds
//!     `round(mtime)`;
//!   * names / link names longer than 100 characters or not pure ASCII go into the pax header as
//!     `path` / `linkpath` (the ustar field keeps the first 100 bytes of the ASCII-`replace`
//!     encoding); sizes >= 8 GiB go into `size`;
//!   * directory names get a trailing `/`;
//!   * uid/gid 0, empty uname/gname, device fields NUL-filled (not CHR/BLK);
//!   * `close()` writes two zero blocks and pads to a multiple of `RECORDSIZE` (10240).

use std::io::{self, Write};

const BLOCKSIZE: usize = 512;
const RECORDSIZE: u64 = 20 * BLOCKSIZE as u64;
const LENGTH_NAME: usize = 100;
const LENGTH_LINK: usize = 100;

/// python `str(float)` (`repr`): the shortest string that round-trips, `.0` for integral
/// values. Only for the "normal" range (no exponent), which covers timestamps.
pub fn py_float_repr(v: f64) -> String {
    let s = format!("{v}");
    if s.contains('.') || s.contains('e') || s.contains("inf") || s.contains("NaN") { s } else { format!("{s}.0") }
}

/// python's `round(float)` to an int (ties to even).
fn py_round(v: f64) -> i128 {
    let r = v.round();
    if (v - v.trunc()).abs() == 0.5 {
        // ties to even
        let t = v.trunc();
        if (t as i128) % 2 == 0 { t as i128 } else { r as i128 }
    } else {
        r as i128
    }
}

/// python `itn(n, digits, format)` for non-negative values that fit (`"%0*o" % (digits-1, n) + NUL`).
fn itn(out: &mut [u8], n: u64) {
    let digits = out.len();
    let s = format!("{:0width$o}", n, width = digits - 1);
    out[..digits - 1].copy_from_slice(&s.as_bytes()[s.len() - (digits - 1)..]);
    out[digits - 1] = 0;
}

/// python `stn(s, length, "ascii", "replace")`: ASCII-encode (non-ASCII code points -> `?`),
/// truncate / NUL-pad to `out.len()`.
fn stn_ascii(out: &mut [u8], s: &str) {
    let mut i = 0;
    for c in s.chars() {
        if i == out.len() {
            break;
        }
        out[i] = if c.is_ascii() { c as u8 } else { b'?' };
        i += 1;
    }
    out[i..].fill(0);
}

/// A member's pax extended header keywords, in python's dict insertion order.
type PaxHeaders = Vec<(&'static str, String)>;

/// python `TarInfo._create_header(info, USTAR_FORMAT, "ascii", "replace")` for our members.
fn ustar_header(name: &str, mode: u32, size: u64, mtime: u64, typeflag: u8, linkname: &str) -> [u8; BLOCKSIZE] {
    let mut b = [0u8; BLOCKSIZE];
    stn_ascii(&mut b[0..100], name);
    itn(&mut b[100..108], (mode & 0o7777) as u64);
    itn(&mut b[108..116], 0); // uid
    itn(&mut b[116..124], 0); // gid
    itn(&mut b[124..136], size);
    itn(&mut b[136..148], mtime);
    b[148..156].copy_from_slice(b"        ");
    b[156] = typeflag;
    stn_ascii(&mut b[157..257], linkname);
    b[257..265].copy_from_slice(b"ustar\x0000"); // POSIX_MAGIC
    // uname, gname (32 NUL each), devmajor/devminor (NUL), prefix (NUL): already zero
    let chksum: u32 = b.iter().map(|&x| x as u32).sum();
    let c = format!("{chksum:06o}\0");
    b[148..155].copy_from_slice(&c.as_bytes()[c.len() - 7..]);
    b
}

/// python `TarInfo._create_pax_generic_header(pax_headers, XHDTYPE, encoding)`.
fn pax_header(pax: &PaxHeaders) -> Vec<u8> {
    let mut records = Vec::new();
    for (k, v) in pax {
        let l = k.len() + v.len() + 3;
        let mut p = 0usize;
        loop {
            let n = l + p.to_string().len();
            if n == p {
                break;
            }
            p = n;
        }
        records.extend_from_slice(p.to_string().as_bytes());
        records.push(b' ');
        records.extend_from_slice(k.as_bytes());
        records.push(b'=');
        records.extend_from_slice(v.as_bytes());
        records.push(b'\n');
    }
    let mut out = ustar_header("././@PaxHeader", 0, records.len() as u64, 0, b'x', "").to_vec();
    let pad = (BLOCKSIZE - records.len() % BLOCKSIZE) % BLOCKSIZE;
    out.extend_from_slice(&records);
    out.resize(out.len() + pad, 0);
    out
}

/// Streaming python-`tarfile` (PAX format) writer. All members share one `mtime` (a python
/// float, e.g. `time.time()`), like `linux.pagecache.RecoverFs`.
pub struct PyTarWriter<W: Write> {
    w: W,
    offset: u64,
    mtime_repr: String,
    mtime_int: u64,
    /// bytes of the current regular file still expected
    pending: u64,
    /// padding owed after the current file's content
    pad: usize,
}

impl<W: Write> PyTarWriter<W> {
    /// `tarfile.open(fileobj=w, mode="w|...")`; members get `mtime` (python float).
    pub fn new(w: W, mtime: f64) -> PyTarWriter<W> {
        let r = py_round(mtime);
        PyTarWriter { w, offset: 0, mtime_repr: py_float_repr(mtime), mtime_int: r.clamp(0, u64::MAX as i128) as u64, pending: 0, pad: 0 }
    }

    /// Bytes written to the tar stream so far (python `TarFile.offset`).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.offset += b.len() as u64;
        self.w.write_all(b)
    }

    /// `tarinfo.tobuf(PAX_FORMAT, "utf-8", "surrogateescape")` + write.
    fn header(&mut self, name: &str, mode: u32, size: u64, typeflag: u8, linkname: &str) -> io::Result<()> {
        assert_eq!(self.pending, 0, "previous file content not complete");
        let mut pax: PaxHeaders = Vec::new();
        if !name.is_ascii() || name.chars().count() > LENGTH_NAME {
            pax.push(("path", name.to_string()));
        }
        if !linkname.is_ascii() || linkname.chars().count() > LENGTH_LINK {
            pax.push(("linkpath", linkname.to_string()));
        }
        let mut hsize = size;
        if size >= 8u64.pow(11) {
            hsize = 0;
            pax.push(("size", size.to_string()));
        }
        let mut mtime = self.mtime_int;
        if mtime >= 8u64.pow(11) {
            mtime = 0;
        }
        pax.push(("mtime", self.mtime_repr.clone()));
        let mut buf = pax_header(&pax);
        buf.extend_from_slice(&ustar_header(name, mode, hsize, mtime, typeflag, linkname));
        self.put(&buf)
    }

    /// `TarInfo(name)` with `type = DIRTYPE`, `mode = 0o755` (`_tar_add_dir`).
    pub fn add_dir(&mut self, name: &str) -> io::Result<()> {
        if name.ends_with('/') { self.header(name, 0o755, 0, b'5', "") } else { self.header(&format!("{name}/"), 0o755, 0, b'5', "") }
    }

    /// `TarInfo(name)` with `type = SYMTYPE`, `linkname`, `mode = 0o444` (`_tar_add_lnk`).
    pub fn add_symlink(&mut self, name: &str, linkname: &str) -> io::Result<()> {
        self.header(name, 0o444, 0, b'2', linkname)
    }

    /// Starts a regular file (`REGTYPE`, `mode = 0o444`) of `size` bytes: write exactly `size`
    /// bytes with [`PyTarWriter::write_content`] / [`PyTarWriter::write_zeros`] afterwards.
    pub fn begin_file(&mut self, name: &str, size: u64) -> io::Result<()> {
        self.header(name, 0o444, size, b'0', "")?;
        self.pending = size;
        self.pad = ((BLOCKSIZE as u64 - size % BLOCKSIZE as u64) % BLOCKSIZE as u64) as usize;
        if size == 0 {
            self.pad = 0;
        }
        Ok(())
    }

    /// Content of the current regular file.
    pub fn write_content(&mut self, data: &[u8]) -> io::Result<()> {
        assert!(data.len() as u64 <= self.pending, "more content than announced");
        self.pending -= data.len() as u64;
        self.put(data)?;
        if self.pending == 0 && self.pad > 0 {
            let z = [0u8; BLOCKSIZE];
            let p = self.pad;
            self.pad = 0;
            self.put(&z[..p])?;
        }
        Ok(())
    }

    /// `n` zero bytes of the current regular file.
    pub fn write_zeros(&mut self, mut n: u64) -> io::Result<()> {
        static Z: [u8; 65536] = [0u8; 65536];
        while n > 0 {
            let k = n.min(Z.len() as u64) as usize;
            self.write_content(&Z[..k])?;
            n -= k as u64;
        }
        Ok(())
    }

    /// `TarFile.close()`: two zero blocks, then zero-pad to a multiple of `RECORDSIZE`.
    /// Returns the inner writer.
    pub fn close(mut self) -> io::Result<W> {
        assert_eq!(self.pending, 0, "file content not complete");
        let z = vec![0u8; RECORDSIZE as usize];
        self.put(&z[..2 * BLOCKSIZE])?;
        let rem = self.offset % RECORDSIZE;
        if rem > 0 {
            let n = (RECORDSIZE - rem) as usize;
            self.put(&z[..n])?;
        }
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_like_python() {
        assert_eq!(py_float_repr(1790380387.3888924), "1790380387.3888924");
        assert_eq!(py_float_repr(1790380387.0), "1790380387.0");
        assert_eq!(py_round(2.5), 2);
        assert_eq!(py_round(3.5), 4);
        assert_eq!(py_round(1790380387.3888924), 1790380387);
    }

    #[test]
    fn headers_like_python_tarfile() {
        // produced by python 3.14: t = tarfile.open(fileobj=b, mode="w"); ti = TarInfo("/x/d");
        // ti.type = DIRTYPE; ti.mode = 0o755; ti.mtime = 1790380387.3888924; t.addfile(ti)
        let mut t = PyTarWriter::new(Vec::new(), 1790380387.3888924);
        t.add_dir("/00000000-0000-0000-0000-000000000000").unwrap();
        let v = t.close().unwrap();
        assert_eq!(v.len(), 10240);
        assert_eq!(&v[0..14], b"././@PaxHeader");
        assert_eq!(&v[124..136], b"00000000034\0");
        assert_eq!(&v[148..156], b"010212\0 ");
        assert_eq!(&v[512..540], b"28 mtime=1790380387.3888924\n");
        assert_eq!(&v[1024..1063], b"/00000000-0000-0000-0000-000000000000/\0");
        assert_eq!(&v[1024 + 136..1024 + 148], b"15255604543\0");
        assert_eq!(&v[1024 + 148..1024 + 156], b"011437\0 ");
        assert_eq!(v[1024 + 156], b'5');
    }
}
