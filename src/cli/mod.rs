//! cli

/// Entry point; returns the process exit code. (CLI agent implements.)
pub fn main() -> i32 {
    println!("{}", crate::VERSION_BANNER);
    0
}
