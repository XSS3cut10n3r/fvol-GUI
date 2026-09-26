//! rsvol: a zero-dependency Rust rewrite of Volatility 3.
//!
//! This is a port of the Volatility 3 memory forensics framework (Copyright Volatility
//! Foundation) and is licensed under the Volatility Software License 1.0.

#![allow(clippy::too_many_arguments)]

pub mod automagic;
pub mod cli;
pub mod codecs;
pub mod context;
pub mod crypto;
pub mod disasm;
pub mod error;
pub mod layers;
pub mod objects;
pub mod plugins;
pub mod renderers;
pub mod symbols;
pub mod util;
pub mod web;
pub mod yara;

/// The banner volatility3 prints as the first line of output.
pub const VERSION_BANNER: &str = "Volatility 3 Framework 2.28.2";

fn main() {
    std::process::exit(cli::main());
}
