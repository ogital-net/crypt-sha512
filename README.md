# crypt-sha512

A `no_std`-compatible Rust implementation of the SHA512-crypt password
hashing algorithm (`$6$` Unix crypt format), ported from
[Ulrich Drepper's reference C implementation][drepper].

The four cryptographic primitives this crate needs — SHA-512, a CSPRNG, a
constant-time comparison, and a non-elidable memory wipe — are delegated to
a backend selected at build time via cargo features. This lets the crate
slot into projects that have already standardized on a particular crypto
stack without dragging in a second one.

[drepper]: https://www.akkadia.org/drepper/SHA-crypt.txt

## Backend selection

**Exactly one** of the following features must be enabled. There is no
default; selecting zero or more than one is a compile error.

| Feature | Stack | Build requirements |
|---|---|---|
| `backend-aws-lc` | [`aws-lc-sys`] | C compiler, `cmake` |
| `backend-boring` | [`boring-sys`] (BoringSSL) | C/C++ compiler, `cmake`, `go` |
| `backend-openssl` | [`openssl-sys`] | OpenSSL headers/libs (`libssl-dev` / `brew install openssl`) |
| `backend-rust-crypto` | [`sha2`] + [`getrandom`] + [`subtle`] + [`zeroize`] | none (pure Rust) |

The public API is identical regardless of backend; switching is a
manifest-only change.

[`aws-lc-sys`]: https://crates.io/crates/aws-lc-sys
[`boring-sys`]: https://crates.io/crates/boring-sys
[`openssl-sys`]: https://crates.io/crates/openssl-sys
[`sha2`]: https://crates.io/crates/sha2
[`getrandom`]: https://crates.io/crates/getrandom
[`subtle`]: https://crates.io/crates/subtle
[`zeroize`]: https://crates.io/crates/zeroize

## Features

- **`no_std`-compatible** — only requires `alloc`.
- **Auto-zeroizing input type** — passwords are passed as a [`Password`]
  newtype whose `Drop` impl wipes the backing buffer with the backend's
  non-elidable zeroing primitive (`OPENSSL_cleanse` for the FFI backends,
  `zeroize::Zeroize` for `backend-rust-crypto`).
- **Timing-attack resistant** — verification compares with the backend's
  constant-time `memcmp`.
- **Cryptographically secure salts** — generated with the backend's CSPRNG.
- **Unix `$6$` compatible** — output is bit-identical to glibc / libxcrypt.

## Usage

```toml
[dependencies]
crypt-sha512 = { version = "1.0.0", default-features = false, features = ["backend-aws-lc"] }
```

### Hash a new password

```rust
use crypt_sha512::{hash, Password};

// Default work factor (5000 rounds), random salt
let h = hash(Password::from("hunter2".to_string()), None);

// Higher work factor for more sensitive deployments
let h = hash(Password::from("hunter2".to_string()), Some(100_000));
```

### Verify a password

```rust
use crypt_sha512::{hash, verify, InvalidHash, Password};

let stored = hash(Password::from("correct horse battery staple"), None);

assert_eq!(verify(Password::from("correct horse battery staple"), &stored), Ok(true));
assert_eq!(verify(Password::from("Tr0ub4dor&3"), &stored), Ok(false));

// Malformed hash strings are reported separately from a wrong password.
assert_eq!(verify(Password::from("anything"), "not a hash"), Err(InvalidHash));
```

`verify` distinguishes three outcomes:

- `Ok(true)` — the hash parses and the password matches.
- `Ok(false)` — the hash parses and the password does **not** match.
- `Err(InvalidHash)` — the hash string is malformed; no comparison was
  performed. Useful for handling multiple hash types or detecting data corruption
  separately from authentication failures.

### Hash with an explicit salt (low-level)

For interoperability tests or when you need to control the salt directly:

```rust
use crypt_sha512::{hash_with_salt, Password};

let h = hash_with_salt(Password::from("password"), b"$6$rounds=10000$saltstring");
assert!(h.starts_with("$6$rounds=10000$saltstring$"));
```

## The `Password` type

`Password` is the only way to feed plaintext into this crate's hashing
functions. It deliberately:

- accepts `From<String>`, `From<&str>`, `From<Vec<u8>>`, and
  `Password::from_bytes`;
- **does not** implement `Clone`, so secrets aren't silently duplicated;
- **does not** implement `Display`, and its `Debug` impl elides the contents,
  so secrets can't accidentally land in logs;
- zeroes its buffer with the active backend's non-elidable zeroing primitive
  on drop — including on panic.

Pass it by value into `hash`, `hash_with_salt`, or `verify`; the function
takes ownership and the buffer is wiped before the call returns.

## Hash format

```text
$6$[rounds=N$]salt$digest
```

- `$6$` — SHA512-crypt identifier.
- `rounds=N$` — optional; default is 5000. Values are clamped into
  `[1000, 999_999_999]` per the SHA-crypt spec.
- `salt` — up to 16 bytes from the crypt base64 alphabet.
- `digest` — 86 bytes, crypt base64.

## MSRV

Rust **1.81**.

## License

BSD 2-Clause. See the `LICENSE` file in the repository.

## Provenance

The hashing algorithm is a direct port of Ulrich Drepper's public-domain
SHA-crypt reference implementation. The `b64_from_24bit` macro mirrors the
shape of the original C macro; tests reuse Drepper's published vectors.
