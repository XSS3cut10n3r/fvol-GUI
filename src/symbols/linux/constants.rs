//! python `framework/constants/linux/__init__.py` values used by the Linux helpers
//! (modules, kallsyms, ...). Other agents may append here.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).

/// python `linux_constants.KERNEL_NAME` (the name of the kernel "module" in module lookups).
pub const KERNEL_NAME: &str = "__kernel__";

/// python `MODULE_MAXIMUM_CORE_SIZE`.
pub const MODULE_MAXIMUM_CORE_SIZE: i128 = 20_000_000;
/// python `MODULE_MAXIMUM_CORE_TEXT_SIZE`.
pub const MODULE_MAXIMUM_CORE_TEXT_SIZE: i128 = 20_000_000;
/// python `MODULE_MINIMUM_SIZE`.
pub const MODULE_MINIMUM_SIZE: i128 = 4096;

/// python `KSYM_NAME_LEN`.
pub const KSYM_NAME_LEN: u64 = 512;

/// python `ATTRIBUTE_NAME_MAX_SIZE`.
pub const ATTRIBUTE_NAME_MAX_SIZE: u64 = 255;

/// python `NM_TYPES_DESC` (nm symbol type letter -> description), in python dict order.
pub const NM_TYPES_DESC: [(&str, &str); 19] = [
    ("a", "Symbol is absolute and doesn't change during linking"),
    ("b", "Symbol in the BSS section, typically holding zero-initialized or uninitialized data"),
    ("c", "Symbol is common, typically holding uninitialized data"),
    ("d", "Symbol is in the initialized data section"),
    ("g", "Symbol is in an initialized data section for small objects"),
    ("i", "Symbol is an indirect reference to another symbol"),
    ("N", "Symbol is a debugging symbol"),
    ("n", "Symbol is in a non-data, non-code, non-debug read-only section"),
    ("p", "Symbol is in a stack unwind section"),
    ("r", "Symbol is in a read only data section"),
    ("s", "Symbol is in an uninitialized or zero-initialized data section for small objects"),
    ("t", "Symbol is in the text (code) section"),
    ("U", "Symbol is undefined"),
    ("u", "Symbol is a unique global symbol"),
    ("V", "Symbol is a weak object, with a default value"),
    ("v", "Symbol is a weak object"),
    ("W", "Symbol is a weak symbol but not marked as a weak object symbol, with a default value"),
    ("w", "Symbol is a weak symbol but not marked as a weak object symbol"),
    ("?", "Symbol type is unknown"),
];

/// python `NM_TYPES_DESC.get(key)`.
pub fn nm_type_desc(key: &str) -> Option<&'static str> {
    NM_TYPES_DESC.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}
