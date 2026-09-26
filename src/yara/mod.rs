//! Pattern matching engines for rsvol (std only, SIMD via std::arch).
//!
//! * [`regex`] — python-`re` compatible regex engine over bytes (what volatility3's
//!   `RegExScanner`, `regexscan`, `vadregexscan`, `vmaregexscan` use):
//!   ```ignore
//!   use crate::yara::regex::{Regex, Flags};
//!   let re = Regex::new(br"[a-z]{5,}\.exe", Flags::S)?;   // re.compile(p, re.DOTALL)
//!   for (start, end) in re.find_iter(chunk) { ... }         // re.finditer
//!   re.search(buf, 0);  re.match_at(buf, 0);                // pattern.search / .match
//!   re.captures_at(buf, 0);                                 // m.span(i) for all groups
//!   ```
//!   Errors mirror python's `re.error` (message text is informative only). `Regex` is
//!   `Sync`: share one per pattern across scanning threads.
//! * [`rules`] — YARA rule compiler + condition evaluator with yara-python-like results
//!   (`Rules::compile(src)?.scan(data)` ~ `yara.compile(source=src).match(data=data)`),
//!   plus volatility3's `YaraScanner` glue.
//! * [`scan`] — YARA string matching engine (text strings + Aho-Corasick [`aho`];
//!   hex / regex strings via [`yre`], a libyara-exact port of the RE machinery).
//! * [`memchr`], [`teddy`] — SIMD byte / substring / byte-set / multi-literal search.

pub mod aho;
pub mod memchr;
pub mod regex;
pub mod rules;
pub mod scan;
pub mod teddy;
pub mod yre;

#[cfg(test)]
mod benchdrv;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod smoke;
#[cfg(test)]
mod smoke_cases;
