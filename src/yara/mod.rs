//! Pattern matching engines: a python-`re` compatible regex engine over bytes
//! (`regex`), fast byte/substring search primitives (`memchr`), and a YARA rule
//! compiler + scanner (`rules`).

pub mod memchr;
pub mod regex;
