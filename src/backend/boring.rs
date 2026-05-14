//! BoringSSL backend (`boring-sys`).
//!
//! BoringSSL exposes the same SHA512 / CRYPTO_memcmp / RAND_bytes /
//! OPENSSL_cleanse FFI as aws-lc (which is itself a fork of BoringSSL),
//! so this module is structurally identical to the aws-lc backend.

use core::mem::MaybeUninit;

pub(crate) struct Sha512Context {
    ctx: boring_sys::SHA512_CTX,
}

impl Sha512Context {
    pub(crate) fn new() -> Self {
        let mut ctx = MaybeUninit::uninit();
        // SAFETY: SHA512_Init initializes every field of SHA512_CTX.
        unsafe {
            boring_sys::SHA512_Init(ctx.as_mut_ptr());
            Self {
                ctx: ctx.assume_init(),
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: data pointer/length describe a valid readable region.
        unsafe {
            boring_sys::SHA512_Update(
                &mut self.ctx,
                data.as_ptr().cast::<core::ffi::c_void>(),
                data.len(),
            );
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 64] {
        let mut result = [0u8; 64];
        // SAFETY: 64-byte writable buffer matches SHA512_DIGEST_LENGTH.
        unsafe {
            boring_sys::SHA512_Final(result.as_mut_ptr(), &mut self.ctx);
        }
        result
    }
}

impl Drop for Sha512Context {
    fn drop(&mut self) {
        // SAFETY: SHA512_CTX is plain old data.
        unsafe {
            boring_sys::OPENSSL_cleanse(
                (&mut self.ctx as *mut boring_sys::SHA512_CTX).cast::<core::ffi::c_void>(),
                core::mem::size_of::<boring_sys::SHA512_CTX>(),
            );
        }
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY: pointers/length describe valid readable regions of equal size.
    unsafe {
        boring_sys::CRYPTO_memcmp(
            a.as_ptr().cast::<core::ffi::c_void>(),
            b.as_ptr().cast::<core::ffi::c_void>(),
            a.len(),
        ) == 0
    }
}

pub(crate) fn random_bytes(buf: &mut [u8]) {
    // SAFETY: buf is writable for `len` bytes; BoringSSL's RAND_bytes either
    // fills it or aborts the process.
    unsafe {
        boring_sys::RAND_bytes(buf.as_mut_ptr(), buf.len());
    }
}

pub(crate) fn secure_zero_bytes(data: &mut [u8]) {
    if !data.is_empty() {
        // SAFETY: data points to len writable bytes.
        unsafe {
            boring_sys::OPENSSL_cleanse(data.as_mut_ptr().cast::<core::ffi::c_void>(), data.len());
        }
    }
}
