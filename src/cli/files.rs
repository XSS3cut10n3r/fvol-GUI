//! Output files for plugins: volatility3's `CLIFileHandler` naming rules (cli/__init__.py,
//! derived from Volatility 3, Volatility Software License 1.0).
//!
//! The file is created as `<output_dir>/<preferred_name>`; when that name is taken a counter is
//! inserted before the extension (`name-1.ext`, `name-2.ext`, ...), exactly like python's
//! `_get_final_filename`. Creation uses O_EXCL so concurrent writers never clobber each other.

use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::Path;

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
        match OpenOptions::new().write(true).read(true).create_new(true).open(&candidate) {
            Ok(f) => {
                let name = candidate.rsplit('/').next().unwrap_or(&candidate).to_string();
                return Ok((f, name));
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
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
        assert!(create(d, "a/b").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
