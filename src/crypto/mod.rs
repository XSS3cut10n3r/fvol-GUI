//! Cryptographic primitives used by volatility3 plugins.
//!
//! Zero-dependency (std only) implementations of the hash functions, MAC, and block
//! ciphers that volatility3's registry-secrets plugins (`hashdump`, `lsadump`,
//! `cachedump`) and a handful of other plugins pull in from `hashlib` / pycryptodome
//! (`Crypto.Cipher`, `Crypto.Hash`). See each submodule's doc comment for exactly
//! which plugin(s) use it and how.
//!
//! None of these functions panic on malformed input: buffer-oriented APIs that can
//! fail (wrong block alignment) return `crate::error::Result` rather than panicking,
//! per the project's robustness rule.

pub mod aes;
pub mod des;
pub mod hmac;
pub mod md5;
pub mod rc4;
pub mod sha1;
pub mod sha256;
pub mod sha512;

/// Identity that pins `x` to a general-purpose register at this point (an empty
/// `asm!` -- a comment, no instructions). It is an optimization barrier for the
/// two LLVM transforms that hurt these hand-scheduled kernels:
/// - the SLP vectorizer turning independent table lookups (DES rounds, IP/FP)
///   into AVX2 gathers plus a horizontal XOR reduction (measured 2-3x slower
///   than plain loads on Alder Lake);
/// - reassociation moving a constant add *after* a value on the critical path
///   (MD5: `(a + K + M) + f` becomes `(a + M + f) + K`, one extra cycle per step).
#[inline(always)]
pub(crate) fn gpr<T: Gpr>(x: T) -> T {
    x.pin()
}

pub(crate) trait Gpr: Copy {
    fn pin(self) -> Self;
}

macro_rules! impl_gpr {
    ($t:ty, $x86:literal, $arm:literal) => {
        impl Gpr for $t {
            #[inline(always)]
            #[allow(unused_mut)]
            fn pin(mut self) -> Self {
                // Safety: empty asm (a comment); it only claims to read and write
                // the register.
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    std::arch::asm!($x86, inout(reg) self, options(pure, nomem, nostack, preserves_flags));
                }
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    std::arch::asm!($arm, inout(reg) self, options(pure, nomem, nostack, preserves_flags));
                }
                self
            }
        }
    };
}
impl_gpr!(u32, "/* {0:e} */", "/* {0:w} */");
impl_gpr!(u64, "/* {0:r} */", "/* {0:x} */");

// Differential tests against Python hashlib/pycryptodome; the embedded vectors
// (~36 KB) are test-only and excluded from non-test builds.
#[cfg(test)]
mod differential;
#[cfg(test)]
mod vectors;

// Manual throughput measurements (`cargo test --profile fast crypto::bench --
// --ignored --nocapture`); see bench.rs for why there's no bench-harness crate.
#[cfg(test)]
mod bench;

/// Test helper: leave the upper halves of all 16 YMM registers non-zero, like AVX code
/// that returns without `vzeroupper` (for the SHA-NI transition tests).
#[cfg(all(test, target_arch = "x86_64"))]
#[inline(always)]
pub(crate) unsafe fn dirty_upper_ymm() {
    unsafe {
        std::arch::asm!(
            "vpcmpeqb ymm0, ymm0, ymm0", "vpcmpeqb ymm1, ymm1, ymm1", "vpcmpeqb ymm2, ymm2, ymm2", "vpcmpeqb ymm3, ymm3, ymm3",
            "vpcmpeqb ymm4, ymm4, ymm4", "vpcmpeqb ymm5, ymm5, ymm5", "vpcmpeqb ymm6, ymm6, ymm6", "vpcmpeqb ymm7, ymm7, ymm7",
            "vpcmpeqb ymm8, ymm8, ymm8", "vpcmpeqb ymm9, ymm9, ymm9", "vpcmpeqb ymm10, ymm10, ymm10", "vpcmpeqb ymm11, ymm11, ymm11",
            "vpcmpeqb ymm12, ymm12, ymm12", "vpcmpeqb ymm13, ymm13, ymm13", "vpcmpeqb ymm14, ymm14, ymm14", "vpcmpeqb ymm15, ymm15, ymm15",
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _, out("ymm4") _, out("ymm5") _, out("ymm6") _, out("ymm7") _,
            out("ymm8") _, out("ymm9") _, out("ymm10") _, out("ymm11") _, out("ymm12") _, out("ymm13") _, out("ymm14") _, out("ymm15") _,
            options(nomem, nostack, preserves_flags)
        )
    };
}
