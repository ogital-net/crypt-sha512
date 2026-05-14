//! Crypto backend dispatch.
//!
//! Each backend exposes the same crate-private API:
//!
//! - [`Sha512Context`] with `new` / `update` / `finish`
//! - [`constant_time_eq`]
//! - [`random_bytes`]
//! - [`secure_zero_bytes`]
//!
//! Exactly one of the `backend-*` features must be enabled; the
//! mutual-exclusion check lives in `lib.rs`.

#[cfg(feature = "backend-aws-lc")]
mod aws_lc;
#[cfg(feature = "backend-aws-lc")]
pub(crate) use aws_lc::*;

#[cfg(feature = "backend-boring")]
mod boring;
#[cfg(feature = "backend-boring")]
pub(crate) use boring::*;

#[cfg(feature = "backend-openssl")]
mod openssl;
#[cfg(feature = "backend-openssl")]
pub(crate) use openssl::*;

#[cfg(feature = "backend-rust-crypto")]
mod rust_crypto;
#[cfg(feature = "backend-rust-crypto")]
pub(crate) use rust_crypto::*;
