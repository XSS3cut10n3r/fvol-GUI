//! Crate-wide error type.
//!
//! Errors on hot paths (invalid address reads during scanning/validation) must be
//! allocation-free, so `InvalidAddress` carries only integers.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// A read touched an address that is not mapped / not present in the layer
    /// (volatility3 `InvalidAddressException` / `PagedInvalidAddressException`).
    InvalidAddress { addr: u64 },
    /// Page is swapped out (volatility3 `SwappedInvalidAddressException`).
    Swapped { addr: u64 },
    /// A symbol or type could not be found (volatility3 `SymbolError`).
    Symbol(String),
    /// Requirements could not be satisfied (automagic failed, missing kernel, ...).
    Unsatisfied(String),
    /// Layer could not be stacked / file format error.
    Layer(String),
    Io(std::io::Error),
    /// Anything else.
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    #[inline]
    pub fn invalid(addr: u64) -> Error {
        Error::InvalidAddress { addr }
    }
    pub fn msg<S: Into<String>>(s: S) -> Error {
        Error::Msg(s.into())
    }
    pub fn symbol<S: Into<String>>(s: S) -> Error {
        Error::Symbol(s.into())
    }
    /// True for InvalidAddress / Swapped (the errors vol3 plugins usually swallow).
    #[inline]
    pub fn is_invalid_address(&self) -> bool {
        matches!(self, Error::InvalidAddress { .. } | Error::Swapped { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidAddress { addr } => write!(f, "Invalid address at {addr:#x}"),
            Error::Swapped { addr } => write!(f, "Swapped out address at {addr:#x}"),
            Error::Symbol(s) => write!(f, "Symbol error: {s}"),
            Error::Unsatisfied(s) => write!(f, "Unsatisfied requirement: {s}"),
            Error::Layer(s) => write!(f, "Layer error: {s}"),
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Msg(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(_: std::fmt::Error) -> Self {
        Error::Msg("formatting error".into())
    }
}
