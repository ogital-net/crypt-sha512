//! Pure-Rust backend using the RustCrypto stack.
//!
//! - SHA-512 from [`sha2`].
//! - Constant-time comparison from [`subtle`].
//! - CSPRNG from [`getrandom`].
//! - Secure zeroing from [`zeroize`].
//!
//! The SHA-512 context's internal state is zeroed on drop via the
//! `zeroize` feature of `sha2`. Other sensitive intermediate buffers
//! (`result`, `p_bytes`, `s_bytes`, the caller's
//! [`Password`](crate::Password)) are wiped via [`secure_zero_bytes`]
//! before they go out of scope.

use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub(crate) struct Sha512Context {
    inner: Sha512,
}

impl Sha512Context {
    pub(crate) fn new() -> Self {
        Self {
            inner: Sha512::new(),
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finish(self) -> [u8; 64] {
        // GenericArray<u8, U64> -> [u8; 64]
        self.inner.finalize().into()
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub(crate) fn random_bytes(buf: &mut [u8]) {
    // Match the FFI backends' "abort on failure" posture: a CSPRNG failure
    // here would mean we're about to ship an attacker-predictable salt, which
    // is never acceptable. Panic loudly.
    getrandom::fill(buf).expect("crypt-sha512: getrandom failed");
}

pub(crate) fn secure_zero_bytes(data: &mut [u8]) {
    // `Zeroize::zeroize` for `[u8]` is implemented with `ptr::write_volatile`
    // plus a `compiler_fence(SeqCst)`. Volatile writes are observable side
    // effects per the Rust abstract machine, so the optimizer is forbidden
    // from eliding them even when `data` is dropped immediately afterward.
    // This is the pure-Rust analog of `OPENSSL_cleanse` used by the FFI
    // backends — do NOT replace with `slice::fill(0)` or a plain loop, both
    // of which LLVM is free to delete as dead stores.
    data.zeroize();
}
