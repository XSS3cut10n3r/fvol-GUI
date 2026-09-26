//! Windows symbol helpers: python `symbols/windows/extensions` class extensions as methods on
//! [`Obj`](crate::objects::Obj), PE helpers, KDBG, version checks, PDB.
//!
//! Derived from Volatility 3 (Volatility Software License 1.0).
//!
//! ```ignore
//! use crate::symbols::windows::prelude::*;
//! let peb = proc.get_peb()?;
//! for m in proc.load_order_modules() { let name = m?.m("BaseDllName")?.get_string()?; }
//! for vad in proc.get_vad_root()?.traverse() { let start = vad?.get_start()?; }
//! ```

pub mod cache;
pub mod consoles;
pub mod ext;
pub mod kdbg;
pub mod objects;
pub mod pdb;
pub mod pe;
pub mod pool;
pub mod registry;
pub mod token;
pub mod vad;
pub mod versions;

pub use ext::{ListIter, WinExt, process_layer};

/// All Windows extension traits (`use crate::symbols::windows::prelude::*;`).
pub mod prelude {
    pub use super::cache::CacheExt;
    pub use super::ext::WinExt;
    pub use super::objects::ObjectsExt;
    pub use super::pool::PoolExt;
    pub use super::token::{KtimerExt, TokenExt};
    pub use super::vad::VadExt;
}
