//! codecs
// STUB module list (core agent) -- the codecs agent's version replaces this file at merge.

pub mod bzip2;
pub mod gzip;
pub mod xz;
pub mod zip;

/// Run `prog args...` with `input` on stdin and return stdout (STUB helper).
pub(crate) fn pipe(prog: &str, args: &[&str], input: &[u8]) -> crate::error::Result<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output()?;
    let _ = writer.join();
    if out.stdout.is_empty() && !out.status.success() {
        return Err(crate::error::Error::msg(format!("{prog} failed")));
    }
    Ok(out.stdout)
}
