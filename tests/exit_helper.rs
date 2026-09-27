//! The real `fvol` binary with and without the exit helper (`src/util/exit.rs`): the helper must
//! not change the exit status, stdout or stderr, and pipes must reach EOF. Runs paths that need
//! no memory image.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn vol(args: &[&str], helper: bool) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fvol"));
    c.args(args);
    if helper {
        c.env_remove("FASTVOL_EXIT_HELPER").env_remove("RSVOL_EXIT_HELPER");
    } else {
        c.env("FASTVOL_EXIT_HELPER", "0");
    }
    c.output().expect("run vol")
}

#[test]
fn exit_helper_keeps_status_and_output() {
    let cases: [&[&str]; 4] = [&["-h"], &["--bogus"], &["-q", "-f", "/nonexistent/image", "windows.info.Info"], &["-q", "no_such_plugin"]];
    for args in cases {
        let (on, off) = (vol(args, true), vol(args, false));
        assert_eq!(on.status.code(), off.status.code(), "{args:?}");
        assert_eq!(on.stdout, off.stdout, "{args:?}");
        assert_eq!(on.stderr, off.stderr, "{args:?}");
    }
}

#[test]
fn exit_helper_closes_the_pipe_with_the_process() {
    // read the (large) help text through a pipe to EOF: it must be complete, and EOF must come
    // right after the process exits, not after some helper that still holds the pipe
    for _ in 0..20 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fvol")).arg("-h").stdout(Stdio::piped()).spawn().expect("spawn");
        let mut out = Vec::new();
        let t = Instant::now();
        child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
        let st = child.wait().unwrap();
        assert!(st.success());
        assert!(out.ends_with(b"\n") && out.len() > 10_000, "{} bytes", out.len());
        assert!(t.elapsed() < Duration::from_secs(10));
    }
}
