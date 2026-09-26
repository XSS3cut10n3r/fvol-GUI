//! The analysis context: global options, the memory layers stacked on the input file,
//! loaded symbol tables, lazily-run automagic results (kernel discovery), and the output
//! file handler.
//!
//! OWNED BY THE CORE AGENT. The CLI relies only on:
//!   * `GlobalOptions` (fields below; add more as needed)
//!   * `Context::new(opts) -> Result<Context>`  (must be cheap: nothing is scanned until a
//!      plugin asks for it)
//!   * `Context::create_output_file(&self, preferred_name) -> Result<(File, String)>`

use crate::error::Result;
use std::fs::File;

/// Global (non plugin-specific) CLI options.
#[derive(Clone, Debug, Default)]
pub struct GlobalOptions {
    /// `-f/--file` (already converted from a path; not a URI)
    pub file: Option<String>,
    /// `--single-location` URI (file:// ...)
    pub single_location: Option<String>,
    /// `--single-swap-locations`
    pub swap_locations: Vec<String>,
    /// `-s/--symbol-dirs` (already split on ';')
    pub symbol_dirs: Vec<String>,
    /// `--cache-path`
    pub cache_path: Option<String>,
    /// `--offline`
    pub offline: bool,
    /// `-u/--remote-isf-url`
    pub remote_isf_url: Option<String>,
    /// `-o/--output-dir` (default ".")
    pub output_dir: String,
    /// `-q/--quiet`
    pub quiet: bool,
    /// `-v` count
    pub verbosity: u8,
    /// `--stackers`
    pub stackers: Option<Vec<String>>,
    /// `--clear-cache`
    pub clear_cache: bool,
}

pub struct Context {
    pub opts: GlobalOptions,
}

impl Context {
    pub fn new(opts: GlobalOptions) -> Result<Context> {
        Ok(Context { opts })
    }

    /// Create a file in the output directory (volatility3 CLIFileHandler semantics: if the
    /// preferred name already exists a counter is appended). Returns the open file and the
    /// final file name (as plugins print it).
    pub fn create_output_file(&self, preferred_name: &str) -> Result<(File, String)> {
        crate::cli::files::create(&self.opts.output_dir, preferred_name)
    }
}
