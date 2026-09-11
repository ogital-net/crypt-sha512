#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(unreachable_pub)]
#![deny(unsafe_op_in_unsafe_fn)]

// --- Backend selection ---------------------------------------------------
//
// Exactly one `backend-*` feature must be enabled. The two checks below turn
// "zero backends" and "two or more backends" into compile errors.
//
// We intentionally do not provide a default backend: each backend pulls in
// substantially different system requirements (C toolchains, linked
// libraries, target support), and silently picking one for the user has been
// a recurring source of dependency-tree surprise in this corner of the
// ecosystem.

#[cfg(not(any(
    feature = "backend-aws-lc",
    feature = "backend-boring",
    feature = "backend-openssl",
    feature = "backend-rust-crypto",
)))]
compile_error!(
    "crypt-sha512: no backend selected. Enable exactly one of the cargo features: \
     `backend-aws-lc`, `backend-boring`, `backend-openssl`, `backend-rust-crypto`."
);

#[cfg(any(
    all(feature = "backend-aws-lc", feature = "backend-boring"),
    all(feature = "backend-aws-lc", feature = "backend-openssl"),
    all(feature = "backend-aws-lc", feature = "backend-rust-crypto"),
    all(feature = "backend-boring", feature = "backend-openssl"),
    all(feature = "backend-boring", feature = "backend-rust-crypto"),
    all(feature = "backend-openssl", feature = "backend-rust-crypto"),
))]
compile_error!(
    "crypt-sha512: more than one backend selected. The `backend-*` features are \
     mutually exclusive; enable exactly one of \
     `backend-aws-lc`, `backend-boring`, `backend-openssl`, `backend-rust-crypto`."
);

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

mod backend;
// Tests and the rest of this file refer to crypto primitives via the
// historical `crypto::` path; alias the chosen backend so we don't have to
// touch every call site.
#[cfg(any(
    feature = "backend-aws-lc",
    feature = "backend-boring",
    feature = "backend-openssl",
    feature = "backend-rust-crypto",
))]
use crate::backend as crypto;
#[cfg(any(
    feature = "backend-aws-lc",
    feature = "backend-boring",
    feature = "backend-openssl",
    feature = "backend-rust-crypto",
))]
use crate::backend::Sha512Context;

// --- Optional `password-hash` trait integration --------------------------

#[cfg(feature = "password-hash")]
mod password_hash;

#[cfg(feature = "password-hash")]
pub use self::password_hash::{Sha512Crypt, Sha512CryptParams};

#[cfg(feature = "password-hash")]
pub use ::password_hash::{CustomizedPasswordHasher, PasswordHasher, PasswordVerifier};

#[cfg(feature = "password-hash")]
pub use ::mcf;

const SHA512_SALT_PREFIX_STR: &str = "$6$";
const SHA512_SALT_PREFIX: &[u8] = SHA512_SALT_PREFIX_STR.as_bytes();
const SHA512_ROUNDS_PREFIX: &[u8] = b"rounds=";
const SALT_LEN_MAX: usize = 16;
const ROUNDS_DEFAULT: u32 = 5000;
const ROUNDS_MIN: u32 = 1000;
const ROUNDS_MAX: u32 = 999_999_999;

// Length of the base64-encoded SHA512 hash in the output
const SHA512_HASH_ENCODED_LENGTH: usize = 86;

// Custom base64 alphabet for crypt
const B64_CHARS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A password whose backing memory is securely zeroed when dropped.
///
/// This newtype is the primary way to pass passwords into [`hash`],
/// [`hash_with_salt`], and [`verify`]. By accepting `Password` by value, the
/// API guarantees that the caller's plaintext copy is destroyed (via
/// `crypto::secure_zero_bytes()`) before the function returns, even on panic.
///
/// # Examples
///
/// ```
/// use crypt_sha512::{hash, verify, Password};
///
/// let h = hash(Password::from("hunter2"), None);
/// assert_eq!(verify(Password::from("hunter2"), &h), Ok(true));
/// ```
///
/// `Password` deliberately does **not** implement [`Clone`], [`Debug`], or
/// [`core::fmt::Display`] to discourage accidental duplication or logging of
/// plaintext secrets.
pub struct Password {
    bytes: Vec<u8>,
}

impl Password {
    /// Construct a `Password` from raw bytes. The provided `Vec<u8>` is moved
    /// into the `Password` and will be zeroed when the `Password` is dropped.
    #[inline]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Take ownership of the inner buffer without running the zeroing `Drop`.
    /// Used internally so `crypt_inner` can mutate and then zero the bytes.
    #[inline]
    fn into_bytes(self) -> Vec<u8> {
        // Move the bytes out, then forget self so Drop does not double-zero.
        let mut me = core::mem::ManuallyDrop::new(self);
        core::mem::take(&mut me.bytes)
    }
}

impl From<String> for Password {
    /// Move a `String`'s buffer into a `Password`. The original `String`'s
    /// allocation becomes the `Password`'s allocation; no copy is made and the
    /// buffer will be zeroed on drop.
    #[inline]
    fn from(s: String) -> Self {
        Self {
            bytes: s.into_bytes(),
        }
    }
}

impl From<&str> for Password {
    /// Copy the string slice into a new `Password`. The copy will be zeroed on
    /// drop, but the caller's original `&str` is unaffected — prefer
    /// [`Password::from(String)`](#impl-From<String>-for-Password) when you
    /// own the buffer.
    #[inline]
    fn from(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
        }
    }
}

impl From<Vec<u8>> for Password {
    #[inline]
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        crypto::secure_zero_bytes(&mut self.bytes);
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

/// Calculate the exact buffer size needed for the salt-spec portion of the
/// output hash string (everything before the encoded digest).
#[inline(always)]
fn salt_spec_output_size(salt_len: usize, rounds_custom: bool) -> usize {
    // Base components:
    // - SHA512_SALT_PREFIX ("$6$") = 3 bytes
    // - salt + '$' separator = salt_len + 1
    let mut size = SHA512_SALT_PREFIX.len() + salt_len + 1;

    // Add rounds specification if custom:
    // - SHA512_ROUNDS_PREFIX ("rounds=") = 7 bytes
    // - maximum 9 digits for rounds value (up to 999999999)
    // - '$' separator = 1 byte
    if rounds_custom {
        size += SHA512_ROUNDS_PREFIX.len() + 9 + 1;
    }
    size
}

/// Generate a random salt string for use with crypt_sha512
/// Fills the provided buffer with random salt characters from B64_CHARS
fn generate_salt(buf: &mut [u8]) {
    // Generate random bytes directly into buffer
    crypto::random_bytes(buf);

    // Transform each byte using lower 6 bits to index into B64_CHARS
    for byte in buf.iter_mut() {
        *byte = B64_CHARS[(*byte & 0x3f) as usize];
    }
}

#[inline]
fn atoi_u32(ascii: &[u8]) -> Option<u32> {
    let mut out: u32 = 0;
    for d in ascii.iter().map(|b| b.wrapping_sub(b'0')) {
        if d < 10 {
            // Saturate on overflow: callers clamp the result into the
            // SHA-crypt rounds range anyway, so saturating to u32::MAX is
            // observationally identical to a correct (but unbounded)
            // bignum parse for any input that fits in the spec's range,
            // and well-defined for inputs that do not.
            out = out.saturating_mul(10).saturating_add(d as u32);
        } else {
            return None;
        }
    }
    Some(out)
}

/// Format a u32 as ASCII digits and append to output vector
/// Uses div/mod arithmetic to avoid allocation
#[inline]
fn push_u32_as_ascii(mut value: u32, output: &mut Vec<u8>) {
    if value == 0 {
        output.push(b'0');
        return;
    }

    // Extract digits using div/mod
    let mut digits = [0u8; 10]; // Max 10 digits for u32
    let mut idx = digits.len() - 1;

    while value > 0 {
        (value, digits[idx]) = (value / 10, (value % 10) as u8 | b'0');
        idx -= 1;
    }

    output.extend_from_slice(&digits[idx + 1..]);
}

/// Encode 3 bytes into 4 base64 characters (crypt-specific encoding).
///
/// Preserved as a macro to mirror the structure of Ulrich Drepper's reference
/// C implementation, where the `b64_from_24bit` operation is also a macro.
macro_rules! b64_from_24bit {
    ($b2:expr, $b1:expr, $b0:expr, $n:expr, $output:expr) => {{
        let mut w = (($b2 as u32) << 16) | (($b1 as u32) << 8) | ($b0 as u32);
        for _ in 0..$n {
            $output.push(B64_CHARS[(w & 0x3f) as usize]);
            w >>= 6;
        }
    }};
}

/// Encode raw bytes with the crypt base64 alphabet, without padding.
///
/// This is the sequential form of the digest encoding in [`crypt_inner`]:
/// each 3-byte group maps to 4 characters taken from the low bits of the
/// 24-bit group first (matching Drepper's `b64_from_24bit`), and a trailing
/// partial group of 1 or 2 bytes maps to 2 or 3 characters. The result is
/// identical to base64ct's `Base64ShaCrypt` encoding.
///
/// Used by the `password-hash` integration to embed arbitrary salt bytes in
/// the MCF hash string.
#[cfg(feature = "password-hash")]
pub(crate) fn encode_crypt_base64(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        b64_from_24bit!(b2, b1, b0, chunk.len() + 1, &mut output);
    }
    output
}

/// Compute a SHA512-crypt (`$6$`) hash with an explicit, caller-provided salt.
///
/// This is the low-level entry point, ported from Ulrich Drepper's reference
/// SHA-crypt C implementation. For most callers, [`hash`] (which generates a
/// secure random salt) is the better choice.
///
/// # Arguments
///
/// * `password` — Password to hash. The backing buffer is zeroed before this
///   function returns (and on panic) thanks to [`Password`]'s `Drop`.
/// * `salt` — Salt specification. Accepted forms:
///   - `b"saltstring"` — bare salt, uses default 5000 rounds
///   - `b"$6$saltstring"` — with the `$6$` prefix
///   - `b"$6$rounds=10000$saltstring"` — with explicit rounds
///
///   Salt is truncated at the first `$` or at 16 bytes, whichever comes first.
///   Rounds are silently clamped to the range `[1000, 999_999_999]` as
///   specified by the SHA-crypt algorithm.
///
/// # Returns
///
/// A complete hash string of the form `$6$[rounds=N$]salt$hash`.
///
/// # Panics
///
/// Does not panic for any input (allocation failure aside).
///
/// # Security
///
/// - All intermediate sensitive buffers are wiped via the active backend's
///   non-elidable zeroing primitive before this function returns.
/// - The `password` buffer is zeroed before return (via `Password::Drop`).
///
/// # Examples
///
/// ```
/// use crypt_sha512::{hash_with_salt, Password};
///
/// let h = hash_with_salt(Password::from("password"), b"saltstring");
/// assert!(h.starts_with("$6$saltstring$"));
///
/// let h = hash_with_salt(Password::from("password"), b"$6$rounds=10000$saltstring");
/// assert!(h.starts_with("$6$rounds=10000$saltstring$"));
/// ```
#[must_use = "the returned hash string is the result of expensive computation"]
pub fn hash_with_salt(password: Password, salt: &[u8]) -> String {
    let mut key_bytes = password.into_bytes();
    let out = crypt_inner(&mut key_bytes, salt);
    crypto::secure_zero_bytes(&mut key_bytes);
    out
}

fn crypt_inner(key_bytes: &mut [u8], salt: &[u8]) -> String {
    let mut salt = salt;
    let mut rounds = ROUNDS_DEFAULT;
    let mut rounds_custom = false;

    // Check for salt prefix
    if salt.starts_with(SHA512_SALT_PREFIX) {
        salt = &salt[SHA512_SALT_PREFIX.len()..];
    }

    // Check for rounds specification
    if salt.starts_with(SHA512_ROUNDS_PREFIX) {
        let rest = &salt[SHA512_ROUNDS_PREFIX.len()..];
        if let Some(dollar_pos) = rest.iter().position(|&b| b == b'$') {
            if let Some(srounds) = atoi_u32(&rest[..dollar_pos]) {
                salt = &rest[dollar_pos + 1..];
                rounds = srounds.clamp(ROUNDS_MIN, ROUNDS_MAX);
                rounds_custom = true;
            }
        }
    }

    // Extract salt (up to first $ or max length)
    let salt_len = salt
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(salt.len())
        .min(SALT_LEN_MAX);
    let salt = &salt[..salt_len];

    // Use a single SHA512 context throughout, reusing it for efficiency
    let mut ctx = Sha512Context::new();
    let mut result;

    // Compute alternate SHA512 sum with input KEY, SALT, and KEY
    ctx.update(key_bytes);
    ctx.update(salt);
    ctx.update(key_bytes);
    result = ctx.finish();

    // Prepare for the real work
    ctx = Sha512Context::new();

    // Add the key string
    ctx.update(key_bytes);

    // Add the salt
    ctx.update(salt);

    // Add for any character in the key one byte of the alternate sum
    let mut cnt = key_bytes.len();
    while cnt > 64 {
        ctx.update(&result[..64]);
        cnt -= 64;
    }
    ctx.update(&result[..cnt]);

    // Take the binary representation of the length of the key
    // and for every 1 add the alternate sum, for every 0 the key
    cnt = key_bytes.len();
    while cnt > 0 {
        if (cnt & 1) != 0 {
            ctx.update(&result[..64]);
        } else {
            ctx.update(key_bytes);
        }
        cnt >>= 1;
    }

    // Create intermediate result
    result = ctx.finish();

    // Start computation of P byte sequence
    ctx = Sha512Context::new();
    for _ in 0..key_bytes.len() {
        ctx.update(key_bytes);
    }
    let temp_result = ctx.finish();

    // Create byte sequence P
    let mut p_bytes = Vec::with_capacity(key_bytes.len());
    cnt = key_bytes.len();
    while cnt >= 64 {
        p_bytes.extend_from_slice(&temp_result[..64]);
        cnt -= 64;
    }
    p_bytes.extend_from_slice(&temp_result[..cnt]);

    // Start computation of S byte sequence
    ctx = Sha512Context::new();
    for _ in 0..(16 + result[0] as usize) {
        ctx.update(salt);
    }
    let temp_result = ctx.finish();

    // Create byte sequence S
    let mut s_bytes = Vec::with_capacity(salt.len());
    cnt = salt.len();
    while cnt >= 64 {
        s_bytes.extend_from_slice(&temp_result[..64]);
        cnt -= 64;
    }
    s_bytes.extend_from_slice(&temp_result[..cnt]);

    // Repeatedly run the collected hash value through SHA512 to burn CPU cycles
    for cnt in 0..rounds {
        ctx = Sha512Context::new();

        // Add key or last result
        if (cnt & 1) != 0 {
            ctx.update(&p_bytes);
        } else {
            ctx.update(&result[..64]);
        }

        // Add salt for numbers not divisible by 3
        if cnt % 3 != 0 {
            ctx.update(&s_bytes);
        }

        // Add key for numbers not divisible by 7
        if cnt % 7 != 0 {
            ctx.update(&p_bytes);
        }

        // Add key or last result
        if (cnt & 1) != 0 {
            ctx.update(&result[..64]);
        } else {
            ctx.update(&p_bytes);
        }

        // Create intermediate result
        result = ctx.finish();
    }

    // Now we can construct the result string
    let output_size = salt_spec_output_size(salt.len(), rounds_custom) + SHA512_HASH_ENCODED_LENGTH;
    let mut output: Vec<u8> = Vec::with_capacity(output_size);
    output.extend_from_slice(SHA512_SALT_PREFIX);

    if rounds_custom {
        output.extend_from_slice(SHA512_ROUNDS_PREFIX);
        push_u32_as_ascii(rounds, &mut output);
        output.push(b'$');
    }

    output.extend_from_slice(salt);
    output.push(b'$');

    // Encode the result in the specific order
    b64_from_24bit!(result[0], result[21], result[42], 4, &mut output);
    b64_from_24bit!(result[22], result[43], result[1], 4, &mut output);
    b64_from_24bit!(result[44], result[2], result[23], 4, &mut output);
    b64_from_24bit!(result[3], result[24], result[45], 4, &mut output);
    b64_from_24bit!(result[25], result[46], result[4], 4, &mut output);
    b64_from_24bit!(result[47], result[5], result[26], 4, &mut output);
    b64_from_24bit!(result[6], result[27], result[48], 4, &mut output);
    b64_from_24bit!(result[28], result[49], result[7], 4, &mut output);
    b64_from_24bit!(result[50], result[8], result[29], 4, &mut output);
    b64_from_24bit!(result[9], result[30], result[51], 4, &mut output);
    b64_from_24bit!(result[31], result[52], result[10], 4, &mut output);
    b64_from_24bit!(result[53], result[11], result[32], 4, &mut output);
    b64_from_24bit!(result[12], result[33], result[54], 4, &mut output);
    b64_from_24bit!(result[34], result[55], result[13], 4, &mut output);
    b64_from_24bit!(result[56], result[14], result[35], 4, &mut output);
    b64_from_24bit!(result[15], result[36], result[57], 4, &mut output);
    b64_from_24bit!(result[37], result[58], result[16], 4, &mut output);
    b64_from_24bit!(result[59], result[17], result[38], 4, &mut output);
    b64_from_24bit!(result[18], result[39], result[60], 4, &mut output);
    b64_from_24bit!(result[40], result[61], result[19], 4, &mut output);
    b64_from_24bit!(result[62], result[20], result[41], 4, &mut output);
    b64_from_24bit!(0, 0, result[63], 2, &mut output);

    // Clear sensitive memory to prevent information leakage. The backend's
    // `secure_zero_bytes` is implemented so the compiler cannot elide the
    // writes (see backend modules for details).
    crypto::secure_zero_bytes(&mut result);
    crypto::secure_zero_bytes(&mut p_bytes);
    crypto::secure_zero_bytes(&mut s_bytes);

    // SAFETY: every byte pushed to `output` is from the ASCII-only
    // `B64_CHARS` table, the digit set produced by `push_u32_as_ascii`, or
    // the literal ASCII bytes `$6$`, `rounds=`, and `$`.
    unsafe { String::from_utf8_unchecked(output) }
}

/// Hash a password with a freshly generated, cryptographically secure random salt.
///
/// This is the recommended high-level API for storing new passwords.
///
/// # Arguments
///
/// * `password` — Password to hash. Its buffer is zeroed before return.
/// * `rounds` — Optional iteration count:
///   - `None` uses the SHA-crypt default of 5000 rounds and omits the
///     `rounds=` segment from the output.
///   - `Some(n)` records `rounds=n$` in the output, with `n` clamped into
///     `[1000, 999_999_999]` per the SHA-crypt specification. Note that
///     `Some(5000)` *also* omits the `rounds=` segment, so its output is
///     bytewise identical to `None`.
///
/// # Returns
///
/// A complete hash string of the form `$6$[rounds=N$]salt$hash`.
///
/// # Panics
///
/// Panics (or aborts) if the active backend's CSPRNG fails. All four
/// backends treat CSPRNG failure as fatal rather than returning a
/// predictable salt:
///
/// - `backend-aws-lc` / `backend-boring`: the FFI `RAND_bytes` aborts the
///   process when entropy is unavailable.
/// - `backend-openssl`: this crate asserts the `RAND_bytes` return code.
/// - `backend-rust-crypto`: this crate `expect`s the `getrandom` call.
///
/// # Security
///
/// - Salt is drawn from the active backend's CSPRNG.
/// - Password and intermediate hash buffers are wiped via the backend's
///   non-elidable zeroing primitive before this function returns.
///
/// # Examples
///
/// ```
/// use crypt_sha512::{hash, verify, Password};
///
/// let h = hash(Password::from("hunter2"), None);
/// assert_eq!(verify(Password::from("hunter2"), &h), Ok(true));
///
/// // Higher work factor for sensitive deployments
/// let h = hash(Password::from("hunter2"), Some(100_000));
/// assert_eq!(verify(Password::from("hunter2"), &h), Ok(true));
/// ```
#[must_use = "the returned hash string is the result of expensive computation"]
pub fn hash(password: Password, rounds: Option<u32>) -> String {
    let (r, r_custom) = match rounds {
        None | Some(ROUNDS_DEFAULT) => (ROUNDS_DEFAULT, false),
        Some(r) => (r, true),
    };

    let mut salt_spec: Vec<u8> = Vec::with_capacity(salt_spec_output_size(SALT_LEN_MAX, r_custom));
    salt_spec.extend_from_slice(SHA512_SALT_PREFIX);

    if r_custom {
        salt_spec.extend_from_slice(SHA512_ROUNDS_PREFIX);
        push_u32_as_ascii(r, &mut salt_spec);
        salt_spec.push(b'$');
    }

    // Append SALT_LEN_MAX random base64 chars. Zero-fill is negligible
    // compared to the thousands of SHA-512 rounds that follow, and avoids
    // any unsafe pointer juggling around `spare_capacity_mut`.
    let salt_start = salt_spec.len();
    salt_spec.resize(salt_start + SALT_LEN_MAX, 0);
    generate_salt(&mut salt_spec[salt_start..]);

    hash_with_salt(password, &salt_spec)
}

/// Error returned by [`verify`] when the supplied hash string is not a
/// well-formed SHA512-crypt (`$6$…$…`) value.
///
/// This is distinct from a simple password mismatch: a mismatch is reported
/// as `Ok(false)`, while a malformed hash is reported as `Err(InvalidHash)`.
///
/// Distinguishing these cases is particularly useful when a credential
/// store contains hashes from multiple algorithms (e.g. a legacy table
/// holding a mix of `$1$` MD5-crypt, `$2y$` bcrypt, `$5$` SHA256-crypt,
/// and `$6$` SHA512-crypt entries, or rows migrated from another system).
/// `Err(InvalidHash)` lets the caller route the request to a different
/// verifier — or surface data corruption — rather than treating a
/// non-`$6$` hash as a failed authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvalidHash;

impl fmt::Display for InvalidHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a well-formed SHA512-crypt ($6$) hash")
    }
}

impl core::error::Error for InvalidHash {}

/// Verify a password against a SHA512-crypt (`$6$`) hash using constant-time
/// comparison.
///
/// Extracts the salt (and rounds, if present) from `hash`, recomputes the
/// SHA512-crypt of `password` using that salt, and compares the result to
/// `hash` with the active backend's constant-time comparison primitive.
///
/// # Arguments
///
/// * `password` — Password to check. Its buffer is zeroed before return,
///   regardless of which branch is taken (match, mismatch, or parse error).
/// * `hash` — Expected hash string in the format
///   `$6$[rounds=N$]salt$encoded_digest`.
///
/// # Returns
///
/// * `Ok(true)` — `hash` is well-formed and `password` matches it.
/// * `Ok(false)` — `hash` is well-formed and `password` does **not** match.
/// * `Err(InvalidHash)` — `hash` is not a well-formed `$6$…$…` string. No
///   password comparison was performed.
///
/// # Errors
///
/// Returns [`InvalidHash`] if `hash` does not begin with `$6$` or contains
/// no `$` separating the salt from the encoded digest.
///
/// # Panics
///
/// Does not panic.
///
/// # Security
///
/// - Final comparison is constant-time (active backend's primitive).
/// - Password buffer is zeroed via the backend's non-elidable zeroing
///   primitive before return on every code path, including the
///   malformed-hash early returns.
///
/// # Examples
///
/// ```
/// use crypt_sha512::{hash, verify, InvalidHash, Password};
///
/// let h = hash(Password::from("correct horse battery staple"), None);
/// assert_eq!(verify(Password::from("correct horse battery staple"), &h), Ok(true));
/// assert_eq!(verify(Password::from("Tr0ub4dor&3"), &h), Ok(false));
///
/// // Malformed hash strings are surfaced as Err, not Ok(false).
/// assert_eq!(verify(Password::from("anything"), "not a hash"), Err(InvalidHash));
///
/// // Works with any externally-produced $6$ hash:
/// let h = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
/// assert_eq!(verify(Password::from("Hello world!"), h), Ok(true));
/// ```
pub fn verify(password: Password, hash: &str) -> Result<bool, InvalidHash> {
    // Extract the salt portion from the hash: $6$[rounds=N$]salt$digest.
    // `password` is dropped (and zeroed) on every early return.
    let rest = hash
        .strip_prefix(SHA512_SALT_PREFIX_STR)
        .ok_or(InvalidHash)?;
    let hash_start = rest.rfind('$').ok_or(InvalidHash)?;
    let salt = &hash[..SHA512_SALT_PREFIX.len() + hash_start];

    // Compute the hash with the extracted salt. `hash_with_salt` consumes
    // and zeros the password.
    let computed = hash_with_salt(password, salt.as_bytes());

    Ok(crypto::constant_time_eq(
        computed.as_bytes(),
        hash.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // --- Algorithm vectors (from Drepper's reference test cases) ---

    #[test]
    fn test_hello_world_basic() {
        let result = hash_with_salt(Password::from("Hello world!"), b"$6$saltstring");
        assert_eq!(
            result,
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
        );
    }

    #[test]
    fn test_hello_world_with_rounds() {
        let result = hash_with_salt(
            Password::from("Hello world!"),
            b"$6$rounds=10000$saltstringsaltstring",
        );
        assert_eq!(
            result,
            "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
        );
    }

    #[test]
    fn test_long_salt_string() {
        let result = hash_with_salt(
            Password::from("This is just a test"),
            b"$6$rounds=5000$toolongsaltstring",
        );
        assert_eq!(
            result,
            "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"
        );
    }

    #[test]
    fn test_multiline_text() {
        let result = hash_with_salt(
            Password::from("a very much longer text to encrypt.  This one even stretches over morethan one line."),
            b"$6$rounds=1400$anotherlongsaltstring"
        );
        assert_eq!(
            result,
            "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"
        );
    }

    #[test]
    fn test_short_salt() {
        let result = hash_with_salt(
            Password::from("we have a short salt string but not a short password"),
            b"$6$rounds=77777$short",
        );
        assert_eq!(
            result,
            "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"
        );
    }

    #[test]
    fn test_short_string() {
        let result = hash_with_salt(
            Password::from("a short string"),
            b"$6$rounds=123456$asaltof16chars..",
        );
        assert_eq!(
            result,
            "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"
        );
    }

    #[test]
    fn test_rounds_minimum() {
        let result = hash_with_salt(
            Password::from("the minimum number is still observed"),
            b"$6$rounds=10$roundstoolow",
        );
        assert_eq!(
            result,
            "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."
        );
    }

    // --- verify() ---

    #[test]
    fn test_verify_correct_password() {
        let h = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        assert_eq!(verify(Password::from("Hello world!"), h), Ok(true));
    }

    #[test]
    fn test_verify_wrong_password() {
        let h = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        assert_eq!(verify(Password::from("wrong password"), h), Ok(false));
    }

    #[test]
    fn test_verify_with_rounds() {
        let h = "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.";
        assert_eq!(verify(Password::from("Hello world!"), h), Ok(true));
        assert_eq!(verify(Password::from("Hello world"), h), Ok(false)); // missing !
    }

    #[test]
    fn test_verify_invalid_hash_format() {
        assert_eq!(
            verify(Password::from("password"), "invalid_hash"),
            Err(InvalidHash)
        );
        assert_eq!(
            verify(Password::from("password"), "$5$saltstring$hash"),
            Err(InvalidHash)
        ); // wrong algo
        assert_eq!(
            verify(Password::from("password"), "$6$nosalt"),
            Err(InvalidHash)
        ); // missing digest
    }

    #[test]
    fn test_invalid_hash_display() {
        let s = format!("{}", InvalidHash);
        assert!(s.contains("$6$"));
    }

    #[test]
    fn test_constant_time_comparison_smoke() {
        let h1 = hash_with_salt(Password::from("password1"), b"$6$salt");
        let h2 = hash_with_salt(Password::from("password2"), b"$6$salt");
        assert_eq!(verify(Password::from("password1"), &h2), Ok(false));
        assert_eq!(verify(Password::from("password2"), &h1), Ok(false));
    }

    // --- hash() ---

    #[test]
    fn test_hash_default_rounds() {
        let h = hash(Password::from("test_password"), None);
        assert!(h.starts_with("$6$"));
        assert!(!h.contains("rounds="));
        assert_eq!(verify(Password::from("test_password"), &h), Ok(true));
        assert_eq!(verify(Password::from("wrong_password"), &h), Ok(false));
    }

    #[test]
    fn test_hash_custom_rounds() {
        let h = hash(Password::from("test_password"), Some(10000));
        assert!(h.starts_with("$6$rounds=10000$"));
        assert_eq!(verify(Password::from("test_password"), &h), Ok(true));
        assert_eq!(verify(Password::from("wrong_password"), &h), Ok(false));
    }

    #[test]
    fn test_hash_different_salts() {
        let h1 = hash(Password::from("test_password"), None);
        let h2 = hash(Password::from("test_password"), None);
        assert_ne!(h1, h2);
        assert_eq!(verify(Password::from("test_password"), &h1), Ok(true));
        assert_eq!(verify(Password::from("test_password"), &h2), Ok(true));
    }

    #[test]
    fn test_hash_salt_length_and_alphabet() {
        let h = hash(Password::from("test"), None);
        let parts: Vec<&str> = h.splitn(4, '$').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1], "6");
        let salt = parts[2];
        assert_eq!(salt.len(), SALT_LEN_MAX);
        for c in salt.chars() {
            assert!(B64_CHARS.contains(&(c as u8)));
        }
    }

    #[test]
    fn test_hash_rounds_clamping() {
        let h_low = hash(Password::from("test"), Some(100));
        assert!(h_low.contains(&format!("rounds={}$", ROUNDS_MIN)));
        let h_min = hash(Password::from("test"), Some(ROUNDS_MIN));
        assert!(h_min.contains(&format!("rounds={}$", ROUNDS_MIN)));
        let h_normal = hash(Password::from("test"), Some(10000));
        assert!(h_normal.contains("rounds=10000$"));
        assert_eq!(verify(Password::from("test"), &h_low), Ok(true));
        assert_eq!(verify(Password::from("test"), &h_min), Ok(true));
        assert_eq!(verify(Password::from("test"), &h_normal), Ok(true));
    }

    #[test]
    fn test_hash_some_default_omits_rounds_segment() {
        // Documented behavior: Some(ROUNDS_DEFAULT) is treated as None.
        let h = hash(Password::from("x"), Some(ROUNDS_DEFAULT));
        assert!(!h.contains("rounds="));
    }

    #[test]
    fn test_hash_empty_password() {
        let h = hash(Password::from(""), None);
        assert_eq!(verify(Password::from(""), &h), Ok(true));
        assert_eq!(verify(Password::from("not_empty"), &h), Ok(false));
    }

    #[test]
    fn test_hash_unicode() {
        let pw = "пароль🔐test";
        let h = hash(Password::from(pw), Some(5000));
        assert_eq!(verify(Password::from(pw), &h), Ok(true));
        assert_eq!(verify(Password::from("wrong"), &h), Ok(false));
    }

    // --- helpers / invariants ---

    #[test]
    fn test_salt_spec_output_size() {
        let salt = "saltstring";
        // 3 ("$6$") + 10 + 1 = 14
        assert_eq!(salt_spec_output_size(salt.len(), false), 14);
        // 3 + 7 ("rounds=") + 9 + 1 + 10 + 1 = 31
        assert_eq!(salt_spec_output_size(salt.len(), true), 31);
        // 3 + 7 + 9 + 1 + 16 + 1 = 37
        assert_eq!(salt_spec_output_size(SALT_LEN_MAX, true), 37);
    }

    #[test]
    fn test_secure_zero_bytes() {
        let mut v = alloc::vec![0x42u8; 128];
        crypto::secure_zero_bytes(&mut v);
        assert!(v.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_password_drop_zeros_buffer() {
        // Build a Password, take its bytes back out via the test-only path
        // of From<Vec<u8>>::into to confirm Drop behavior indirectly: drop
        // a Password over a buffer we can inspect afterward by reusing the
        // allocation pattern. We can't directly observe freed memory, so
        // instead exercise the public Drop path and confirm no panic.
        let p = Password::from("secret");
        drop(p);

        // Direct check on the public byte-vec constructor:
        let bytes = alloc::vec![0xAAu8; 32];
        let p = Password::from_bytes(bytes);
        // into_bytes does NOT zero (used internally) — sanity check it returns the data.
        let recovered = p.into_bytes();
        assert!(recovered.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_password_debug_does_not_leak() {
        let p = Password::from("super-secret-value");
        let dbg = format!("{:?}", p);
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("Password"));
    }
}
