//! rsvol: a zero-dependency Rust rewrite of Volatility 3.
//!
//! This is a port of the Volatility 3 memory forensics framework (Copyright Volatility
//! Foundation) and is licensed under the Volatility Software License 1.0.

#![allow(clippy::too_many_arguments)]
// The process entry point is the C `main` below (see there); test builds use libtest's.
#![cfg_attr(not(test), no_main)]

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

#[cfg(not(test))]
unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn poll(fds: *mut [i32; 2], nfds: u64, timeout: i32) -> i32;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
}

/// The C entry point (`#![no_main]`). std's `lang_start` runtime setup is ~4% of a warm
/// `windows.pslist` run: its stack-overflow handler finds the main thread's stack with
/// `pthread_getattr_np`, which parses /proc/self/maps with sscanf (~110k instructions, 8
/// syscalls), and installs an alternate signal stack (mmap + mprotect + sigaltstack).
/// Only the parts with observable effects are kept: closed standard fds are reopened on
/// /dev/null and SIGPIPE is ignored (writes to a closed pipe fail with EPIPE), exactly as std
/// does. Arguments still come from glibc's `.init_array` hook, and `process::exit` flushes
/// stdout like a return from a Rust `main`. A stack overflow now ends in a plain SIGSEGV
/// instead of std's message + SIGABRT; an escaping panic still exits with status 101.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    // a detached helper building a symbol table blob (see symbols::store::finish_deferred)
    if let Some(spec) = std::env::var_os(symbols::store::HELPER_ENV) {
        std::process::exit(symbols::store::run_helper(&spec));
    }
    // std::sys::pal::unix::init: sanitize_standard_fds + reset_sigpipe
    const POLLNVAL: i32 = 0x20;
    const O_RDWR: i32 = 2;
    const SIGPIPE: i32 = 13;
    const SIG_IGN: usize = 1;
    let mut fds = [[0i32, 0], [1, 0], [2, 0]]; // struct pollfd { fd, events | revents << 16 }
    unsafe {
        if poll(fds.as_mut_ptr(), 3, 0) >= 0 {
            for pfd in fds {
                if (pfd[1] >> 16) & POLLNVAL != 0 && open(c"/dev/null".as_ptr(), O_RDWR, 0) < 0 {
                    std::process::abort();
                }
            }
        }
        signal(SIGPIPE, SIG_IGN);
    }
    let code = std::panic::catch_unwind(cli::main).unwrap_or(101);
    // background cache writes finish after the output, before exit
    use std::io::Write;
    let _ = std::io::stdout().flush();
    // the output is complete: now the blobs of lazily loaded symbol tables
    symbols::store::finish_deferred();
    util::bg::join_all();
    // no worker thread outlives the run into the teardown hand-off
    util::pool::shutdown();
    // nothing is written after this: the address-space teardown moves to a helper process
    util::exit::detach_teardown();
    std::process::exit(code)
}
