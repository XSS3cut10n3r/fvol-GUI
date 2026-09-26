//! Pattern matching engines:
//! * `regex`   — python-`re` compatible regex engine over bytes (lazy DFA + backtracker);
//! * `memchr`  — SIMD byte / substring / byte-set search primitives;
//! * `aho`     — Aho-Corasick multi-pattern search;
//! * `scan`    — YARA string matching engine (text / hex / regex strings);
//! * `rules`   — YARA rule language (compiler + condition evaluator + yara-python-like API).

pub mod aho;
pub mod memchr;
pub mod regex;
pub mod rules;
pub mod scan;
pub mod teddy;
pub mod yre;

#[cfg(test)]
mod benchdrv;
