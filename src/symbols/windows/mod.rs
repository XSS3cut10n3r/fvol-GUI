//! Windows symbol helpers: python `symbols/windows/extensions` class extensions as methods on
//! [`Obj`](crate::objects::Obj) (trait [`WinExt`]), PE helpers, KDBG, version checks, PDB.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::windows::WinExt;
//! let peb = proc.get_peb()?;
//! for m in proc.load_order_modules() { let name = m.m("BaseDllName")?.get_string()?; }
//! ```

pub mod ext;
pub mod kdbg;
pub mod pdb;
pub mod pe;
pub mod versions;

pub use ext::{ListIter, WinExt, process_layer};
