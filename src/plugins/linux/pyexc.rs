//! python exceptions that are not volatility exceptions (`ValueError`, `re.error`,
//! `yara.SyntaxError`, ...) end a python plugin with a traceback: the rows rendered so far are
//! printed, stderr gets the traceback, and stdout gets none of the "\n\n" block the CLI prints
//! for volatility exceptions. rsvol's equivalent is a panic on the rendering thread (the CLI
//! catches it and reports it the same way), raised after the rows python printed.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0) behaviour.

use crate::error::Error;

/// Raise `e` as a python non-volatility exception (never returns).
pub fn py_raise(e: Error) -> ! {
    panic!("{e}")
}

/// True for the errors rsvol reports with a python exception class prefix that python does
/// not catch as a volatility exception (`ValueError: ...`, `re.error: ...`, `yara: ...`).
pub fn is_python_exception(e: &Error) -> bool {
    matches!(e, Error::Msg(m) if m.starts_with("ValueError:") || m.starts_with("re.error:") || m.starts_with("yara:"))
}

/// `py_raise(e)` for python exceptions (see [`is_python_exception`]), else `e` unchanged (to
/// be returned as the plugin's error). Call it on the rendering thread, after emitting the
/// rows python printed before raising.
pub fn raise_if_python(e: Error) -> Error {
    if is_python_exception(&e) {
        py_raise(e)
    }
    e
}
