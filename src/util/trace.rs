//! Tiny timing tracer: set `FASTVOL_TRACE=1` to print `[trace] name: 1.234ms` to stderr when a
//! span ends. Zero cost when disabled (one cached env check).
//!
//! ```ignore
//! let _t = crate::util::trace::span("dtb scan");
//! ```

use std::sync::OnceLock;
use std::time::Instant;

/// Whether tracing is enabled (`FASTVOL_TRACE` set and non-empty).
pub fn enabled() -> bool {
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| crate::util::env::var_os("TRACE").is_some_and(|v| !v.is_empty()))
}

/// A timing span; prints on drop.
pub struct Span {
    name: &'static str,
    start: Instant,
}

impl Drop for Span {
    fn drop(&mut self) {
        let d = self.start.elapsed();
        emit(format_args!("[trace] {}: {:.3}ms\n", self.name, d.as_secs_f64() * 1000.0));
    }
}

/// Write a trace line to stderr. Errors are ignored (like python's logging): a closed stderr
/// (`2>&1 | head`) must not turn a diagnostic into a panic, let alone one inside a span's
/// drop while another panic unwinds (which aborts the process).
fn emit(args: std::fmt::Arguments) {
    use std::io::Write;
    let _ = std::io::stderr().write_fmt(args);
}

/// Start a span (None when tracing is disabled).
#[inline]
pub fn span(name: &'static str) -> Option<Span> {
    if enabled() { Some(Span { name, start: Instant::now() }) } else { None }
}

/// Print `[trace] <msg>` when tracing is enabled (the message is only built then).
#[inline]
pub fn note(msg: impl FnOnce() -> String) {
    if enabled() {
        emit(format_args!("[trace] {}\n", msg()));
    }
}
