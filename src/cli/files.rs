//! Output files for plugins: volatility3's `CLIFileHandler` naming rules (cli/__init__.py,
//! derived from Volatility 3, Volatility Software License 1.0).
//!
//! The file is created as `<output_dir>/<preferred_name>`; when that name is taken a counter is
//! inserted before the extension (`name-1.ext`, `name-2.ext`, ...), exactly like python's
//! `_get_final_filename`. Creation uses O_EXCL so concurrent writers never clobber each other.
//!
//! Permissions: python's `CLIDirectFileHandler` writes to a `tempfile.mkstemp()` file (created
//! with mode 0o600, minus the umask) and renames it into place, so dumped files end up 0o600
//! (with any usual umask). [`open_new`] creates files the same way.

use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// python `tempfile.mkstemp`'s file mode (the process umask still applies, as in python).
pub const OUTPUT_FILE_MODE: u32 = 0o600;

/// Create a new output file at `path` (O_EXCL, read + write) with python's permissions
/// ([`OUTPUT_FILE_MODE`] minus the umask).
pub fn open_new(path: impl AsRef<Path>) -> std::io::Result<File> {
    OpenOptions::new().write(true).read(true).create_new(true).mode(OUTPUT_FILE_MODE).open(path)
}

/// python `os.path.splitext` (posix)
pub fn splitext(p: &str) -> (&str, &str) {
    let sep = p.rfind('/').map(|i| i as isize).unwrap_or(-1);
    let dot = match p.rfind('.') {
        Some(d) if d as isize > sep => d,
        _ => return (p, ""),
    };
    // skip leading dots of the file name
    let name_start = (sep + 1) as usize;
    if p[name_start..dot].bytes().all(|b| b == b'.') {
        return (p, "");
    }
    (&p[..dot], &p[dot..])
}

/// python `os.path.join(a, b)` for a relative `b`
fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

/// Create `preferred_name` in `output_dir` (created if missing). Returns the open file and the
/// final file name (basename) that plugins print.
pub fn create(output_dir: &str, preferred_name: &str) -> Result<(File, String)> {
    if preferred_name.contains('/') {
        return Err(Error::msg("FileHandler filenames cannot contain path separators"));
    }
    let dir = if output_dir.is_empty() { "." } else { output_dir };
    std::fs::create_dir_all(dir)?;
    let first = join(dir, preferred_name);
    let (stem, ext) = splitext(&first);
    let mut counter = 0u64;
    loop {
        let candidate = if counter == 0 { first.clone() } else { format!("{stem}-{counter}{ext}") };
        counter += 1;
        // os.path.exists() is false for dangling symlinks; python would then overwrite them
        if Path::new(&candidate).exists() {
            continue;
        }
        match open_new(&candidate) {
            Ok(f) => {
                let name = candidate.rsplit('/').next().unwrap_or(&candidate).to_string();
                return Ok((f, name));
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

// ------------------------------------------------------------------------ sparse dumps

#[repr(C)]
struct IoVec {
    base: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn pwritev(fd: i32, iov: *const IoVec, iovcnt: i32, offset: i64) -> isize;
}

/// Whether `b` is all zero bytes (data pages usually exit on the first word).
#[inline]
pub fn is_zero(b: &[u8]) -> bool {
    // SAFETY: u64 has no invalid bit patterns; align_to splits off the unaligned ends
    let (pre, mid, post) = unsafe { b.align_to::<u64>() };
    pre.iter().all(|&x| x == 0) && post.iter().all(|&x| x == 0) && mid.chunks(8).all(|c| c.iter().fold(0, |a, &x| a | x) == 0)
}

/// Writes layer data into a fresh dump file at given file offsets with exactly the bytes of
/// python's `layer.read(offset, size, pad=True)` + `file.write(...)`: pages that read as
/// zeros are left as holes (which read back as the same zeros, without page-cache traffic),
/// the others go out in large `pwritev` batches straight from the mmapped image.
pub struct SparseDump<'f> {
    file: &'f std::fs::File,
    iov: Vec<IoVec>,
    /// file offsets of the pending batch
    start: u64,
    end: u64,
    /// padded reads referenced by the pending batch
    bufs: Vec<Vec<u8>>,
    /// the size python's file ends up with
    size: u64,
    written_end: u64,
}

impl<'f> SparseDump<'f> {
    const PAGE: u64 = 0x1000;
    const IOV_MAX: usize = 1024;

    pub fn new(file: &'f std::fs::File) -> SparseDump<'f> {
        SparseDump { file, iov: Vec::new(), start: 0, end: 0, bufs: Vec::new(), size: 0, written_end: 0 }
    }

    /// `layer` bytes `[mem, mem + len)` (padded) at file offset `foff`.
    pub fn range(&mut self, layer: &dyn crate::layers::Layer, mem: u64, len: u64, foff: u64) -> std::io::Result<()> {
        self.size = self.size.max(foff.saturating_add(len));
        let mut pos = 0u64;
        while pos < len {
            let m = mem.wrapping_add(pos);
            let n = (len - pos).min(Self::PAGE - (m & (Self::PAGE - 1)));
            let at = foff + pos;
            match layer.slice(m, n as usize) {
                Some(s) => {
                    if !is_zero(s) {
                        self.push(at, s.as_ptr(), s.len())?;
                    }
                }
                None => {
                    let mut b = vec![0u8; n as usize];
                    layer.read_padded(m, &mut b);
                    if !is_zero(&b) {
                        // the buffer must outlive the batch: flush a batch it can't extend first
                        if !self.iov.is_empty() && (at != self.end || self.iov.len() == Self::IOV_MAX) {
                            self.flush()?;
                        }
                        let p = b.as_ptr();
                        self.bufs.push(b);
                        self.push(at, p, n as usize)?;
                    }
                }
            }
            pos += n;
        }
        Ok(())
    }

    #[inline]
    fn push(&mut self, at: u64, p: *const u8, n: usize) -> std::io::Result<()> {
        if !self.iov.is_empty() && (at != self.end || self.iov.len() == Self::IOV_MAX) {
            self.flush()?;
        }
        if self.iov.is_empty() {
            self.start = at;
            self.end = at;
        }
        match self.iov.last_mut() {
            Some(last) if last.base.wrapping_add(last.len) == p => last.len += n,
            _ => self.iov.push(IoVec { base: p, len: n }),
        }
        self.end += n as u64;
        self.written_end = self.written_end.max(self.end);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let (mut first, mut off) = (0usize, self.start);
        while first < self.iov.len() {
            let r = unsafe { pwritev(self.file.as_raw_fd(), self.iov[first..].as_ptr(), (self.iov.len() - first) as i32, off as i64) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                self.iov.clear();
                self.bufs.clear();
                return Err(e);
            }
            if r == 0 {
                self.iov.clear();
                self.bufs.clear();
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            // skip what was written (short writes)
            let mut n = r as usize;
            off += n as u64;
            while n > 0 {
                let v = &mut self.iov[first];
                if n >= v.len {
                    n -= v.len;
                    first += 1;
                } else {
                    v.base = v.base.wrapping_add(n);
                    v.len -= n;
                    n = 0;
                }
            }
        }
        self.iov.clear();
        self.bufs.clear();
        Ok(())
    }

    /// The file is (at least) `size` bytes long, like python's after writing that many.
    pub fn set_size(&mut self, size: u64) {
        self.size = self.size.max(size);
    }

    /// Write what is pending and give the file its full size.
    pub fn finish(mut self) -> std::io::Result<()> {
        self.flush()?;
        if self.written_end < self.size {
            self.file.set_len(self.size)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        assert_eq!(splitext("a/b.c"), ("a/b", ".c"));
        assert_eq!(splitext("a/.bashrc"), ("a/.bashrc", ""));
        assert_eq!(splitext("a/..x"), ("a/..x", ""));
        assert_eq!(splitext("a/x..y"), ("a/x.", ".y"));
        assert_eq!(splitext("a.d/x"), ("a.d/x", ""));
        assert_eq!(splitext("pid.4.dmp"), ("pid.4", ".dmp"));
    }

    #[test]
    fn dedup() {
        let dir = std::env::temp_dir().join(format!("rsvol-files-test-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        let (_, a) = create(d, "x.dmp").unwrap();
        let (_, b) = create(d, "x.dmp").unwrap();
        let (_, c) = create(d, "x.dmp").unwrap();
        assert_eq!((a.as_str(), b.as_str(), c.as_str()), ("x.dmp", "x-1.dmp", "x-2.dmp"));
        // python's mkstemp mode: never group/other accessible, whatever the umask
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("x.dmp")).unwrap().permissions().mode() & 0o177, 0);
        assert!(create(d, "a/b").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
