//! PDB download + PDB -> ISF conversion.
// STUB (core agent): replaced by the pdb agent's implementation at merge.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Download `pdb_name` (GUID/age) from the symbol server (unless `offline`), convert it to an
/// ISF and write it to `dest_dir/windows/<pdb_name>/<GUID>-<age>.json.xz`; returns the path.
pub fn download_and_convert(pdb_name: &str, guid: &str, age: u32, dest_dir: &Path, offline: bool) -> Result<PathBuf> {
    let _ = (dest_dir, offline);
    Err(Error::Unsatisfied(format!("symbol table for {pdb_name} {guid}-{age} not found (PDB download not available)")))
}
