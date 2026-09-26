//! libyara-compatible regular expression machinery for YARA hex and regex strings:
//! parsers (`ast`), code emission (`emit`), fiber / fast executors (`exec`) and atom
//! selection (`atoms`). Derived from the behaviour of libyara 4.5 (BSD-3-Clause).

pub mod ast;
pub mod atoms;
pub mod emit;
pub mod exec;

#[cfg(test)]
mod difftest;
