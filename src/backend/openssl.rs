//! OpenSSL backend (`openssl-sys`).
//!
//! Uses the legacy `SHA512_*` API rather than the EVP interface. These
//! symbols are still exported (though formally deprecated) by OpenSSL 3.x
//! and re-exported by `openssl-sys`. The crypt algorithm only ever feeds
//! short inputs and expects a fixed 64-byte output, so the simpler API is
//! sufficient and avoids EVP_MD lifetime juggling.
//!
//! Unlike BoringSSL/aws-lc, OpenSSL's `RAND_bytes` takes a `c_int` length,
//! so we explicitly convert and check the return code (RAND_bytes can fail).

use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;

// `openssl-sys` 0.9.x does not re-export `OPENSSL_cleanse`. Declare it
// ourselves; the symbol has been part of `<openssl/crypto.h>` since OpenSSL
// 1.0 and remains exported in OpenSSL 3.x. The signature is:
//
//     void OPENSSL_cleanse(void *ptr, size_t len);
extern "C" {
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

pub(crate) struct Sha512Context {
    ctx: openssl_sys::SHA512_CTX,
}

impl Sha512Context {
    pub(crate) fn new() -> Self {
        let mut ctx = MaybeUninit::uninit();
        // SAFETY: SHA512_Init initializes every field of SHA512_CTX.
        unsafe {
            openssl_sys::SHA512_Init(ctx.as_mut_ptr());
            Self {
                ctx: ctx.assume_init(),
            }
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        // SAFETY: data pointer/length describe a valid readable region.
        unsafe {
            openssl_sys::SHA512_Update(&mut self.ctx, data.as_ptr().cast::<c_void>(), data.len());
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 64] {
        let mut result = [0u8; 64];
        // SAFETY: 64-byte writable buffer matches SHA512_DIGEST_LENGTH.
        unsafe {
            openssl_sys::SHA512_Final(result.as_mut_ptr(), &mut self.ctx);
        }
        result
    }
}

impl Drop for Sha512Context {
    fn drop(&mut self) {
        // SAFETY: SHA512_CTX is plain old data.
        unsafe {
            OPENSSL_cleanse(
                (&mut self.ctx as *mut openssl_sys::SHA512_CTX).cast::<c_void>(),
                core::mem::size_of::<openssl_sys::SHA512_CTX>(),
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
        openssl_sys::CRYPTO_memcmp(
            a.as_ptr().cast::<c_void>(),
            b.as_ptr().cast::<c_void>(),
            a.len(),
        ) == 0
    }
}

pub(crate) fn random_bytes(buf: &mut [u8]) {
    // OpenSSL's RAND_bytes takes a `c_int` length and can fail (return 0)
    // if the underlying CSPRNG is not seeded. Refuse to silently ship a
    // zeroed salt.
    let len: c_int = buf
        .len()
        .try_into()
        .expect("crypt-sha512: RNG request larger than c_int::MAX");
    // SAFETY: buf is writable for `len` bytes (`len` derived from buf.len()).
    let rc = unsafe { openssl_sys::RAND_bytes(buf.as_mut_ptr(), len) };
    assert_eq!(rc, 1, "crypt-sha512: OpenSSL RAND_bytes failed");
}

pub(crate) fn secure_zero_bytes(data: &mut [u8]) {
    if !data.is_empty() {
        // SAFETY: data points to len writable bytes.
        unsafe {
            OPENSSL_cleanse(data.as_mut_ptr().cast::<c_void>(), data.len());
        }
    }
}
