//! Optional integration with the RustCrypto [`password_hash`] traits.
//!
//! Enabled by the `password-hash` cargo feature. Provides [`Sha512Crypt`],
//! an implementation of the [`PasswordHasher`], [`CustomizedPasswordHasher`]
//! and [`PasswordVerifier`] traits from the [`password_hash`] crate (version
//! 0.6) for SHA512-crypt (`$6$`), producing and consuming password hash
//! strings in Modular Crypt Format via the [`mcf`] crate.
//!
//! Hashing and verification defer to this crate's reference-port SHA-crypt
//! core, so hashes produced through the traits are computed exactly as by
//! [`hash`][crate::hash] and [`hash_with_salt`][crate::hash_with_salt], and
//! trait-based verification accepts any well-formed `$6$` hash string,
//! including hashes produced by glibc / libxcrypt.
//!
//! # Notes
//!
//! - The traits pass salts around as raw bytes, which cannot necessarily be
//!   embedded in an MCF string. Salt bytes are therefore encoded with the
//!   crypt base64 alphabet before use -- the same convention used by
//!   RustCrypto's `sha-crypt` crate. If you need a *literal* salt string,
//!   use [`hash_with_salt`][crate::hash_with_salt] directly.
//! - An empty salt is rejected with [`Error::SaltInvalid`].
//! - [`PasswordHasher::hash_password`] (random salt) is available when the
//!   `password-hash` crate's `getrandom` feature is enabled. Note that it
//!   draws randomness from the `getrandom` crate directly, not from this
//!   crate's selected backend CSPRNG.
//! - Enabling this feature raises the crate's effective MSRV to Rust 1.85
//!   (the `password-hash` / `mcf` MSRV).
//!
//! # Example
//!
//! ```
//! use crypt_sha512::{PasswordHasher, PasswordVerifier, Sha512Crypt};
//!
//! let hasher = Sha512Crypt::default(); // 5000 rounds
//! let hash = hasher
//!     .hash_password_with_salt(b"hunter2", b"raw salt bytes")
//!     .expect("hashing failed");
//! assert!(hash.as_str().starts_with("$6$"));
//!
//! hasher
//!     .verify_password(b"hunter2", hash.as_str())
//!     .expect("verification failed");
//! ```

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use ::mcf::{PasswordHash, PasswordHashRef};
use ::password_hash::{
    CustomizedPasswordHasher, Error, PasswordHasher, PasswordVerifier, Result, Version,
};

use crate::{
    atoi_u32, crypto, encode_crypt_base64, hash_with_salt, push_u32_as_ascii,
    salt_spec_output_size, Password, ROUNDS_DEFAULT, ROUNDS_MAX, ROUNDS_MIN, SALT_LEN_MAX,
    SHA512_ROUNDS_PREFIX, SHA512_SALT_PREFIX,
};

/// MCF algorithm identifier for SHA512-crypt.
const SHA512_CRYPT_ID: &str = "6";

/// Parameters for SHA512-crypt: the iteration count (`rounds`).
///
/// Valid round counts range from [`Sha512CryptParams::MIN_ROUNDS`] to
/// [`Sha512CryptParams::MAX_ROUNDS`] inclusive; the default is 5000, as
/// specified by the SHA-crypt algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha512CryptParams {
    rounds: u32,
}

impl Sha512CryptParams {
    /// Default parameters (5000 rounds).
    pub const DEFAULT: Self = Self {
        rounds: ROUNDS_DEFAULT,
    };

    /// Minimum permitted round count (1000).
    pub const MIN_ROUNDS: u32 = ROUNDS_MIN;

    /// Maximum permitted round count (999_999_999).
    pub const MAX_ROUNDS: u32 = ROUNDS_MAX;

    /// Create parameters with the given round count.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParamInvalid`] if `rounds` is outside the range
    /// [`MIN_ROUNDS`][Self::MIN_ROUNDS]..=[`MAX_ROUNDS`][Self::MAX_ROUNDS].
    pub const fn new(rounds: u32) -> Result<Self> {
        if rounds >= ROUNDS_MIN && rounds <= ROUNDS_MAX {
            Ok(Self { rounds })
        } else {
            Err(Error::ParamInvalid { name: "rounds" })
        }
    }

    /// The round count.
    pub const fn rounds(self) -> u32 {
        self.rounds
    }
}

impl Default for Sha512CryptParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for Sha512CryptParams {
    /// Formats as an MCF params field, e.g. `rounds=5000`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rounds={}", self.rounds)
    }
}

impl FromStr for Sha512CryptParams {
    type Err = Error;

    /// Parse an MCF params field of the form `rounds=N`. The empty string
    /// yields the default parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParamsInvalid`] if the field does not start with
    /// `rounds=`, and [`Error::ParamInvalid`] if the value is not a valid
    /// round count.
    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Ok(Self::DEFAULT);
        }
        let digits = s.strip_prefix("rounds=").ok_or(Error::ParamsInvalid)?;
        let rounds =
            atoi_u32(digits.as_bytes()).ok_or(Error::ParamInvalid { name: "rounds" })?;
        Self::new(rounds)
    }
}

/// SHA512-crypt (`$6$`) password hasher implementing the RustCrypto
/// [`password_hash`] traits.
///
/// This type holds the default parameters used when hashing through the
/// [`PasswordHasher`] methods; verification works for any well-formed `$6$`
/// hash regardless of how this value is configured.
///
/// # Example
///
/// ```
/// use crypt_sha512::{PasswordHasher, PasswordVerifier, Sha512Crypt, Sha512CryptParams};
///
/// // Custom work factor
/// let params = Sha512CryptParams::new(100_000).expect("valid rounds");
/// let hasher = Sha512Crypt::new(params);
///
/// let hash = hasher
///     .hash_password_with_salt(b"hunter2", b"raw salt bytes")
///     .expect("hashing failed");
/// assert!(hash.as_str().starts_with("$6$rounds=100000$"));
///
/// hasher
///     .verify_password(b"hunter2", hash.as_str())
///     .expect("verification failed");
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sha512Crypt {
    params: Sha512CryptParams,
}

impl Sha512Crypt {
    /// Default configuration: 5000 rounds, the SHA-crypt default.
    pub const DEFAULT: Self = Self::new(Sha512CryptParams::DEFAULT);

    /// Create a hasher using the given parameters for hashing.
    ///
    /// Verification is unaffected by the configured parameters: the rounds
    /// and salt are always taken from the hash being verified.
    pub const fn new(params: Sha512CryptParams) -> Self {
        Self { params }
    }

    /// The parameters this hasher uses when hashing.
    pub const fn params(&self) -> Sha512CryptParams {
        self.params
    }
}

impl From<Sha512CryptParams> for Sha512Crypt {
    fn from(params: Sha512CryptParams) -> Self {
        Self::new(params)
    }
}

impl CustomizedPasswordHasher<PasswordHash> for Sha512Crypt {
    type Params = Sha512CryptParams;

    fn hash_password_customized(
        &self,
        password: &[u8],
        salt: &[u8],
        algorithm: Option<&str>,
        version: Option<Version>,
        params: Sha512CryptParams,
    ) -> Result<PasswordHash> {
        match algorithm {
            None | Some(SHA512_CRYPT_ID) => {}
            Some(_) => return Err(Error::Algorithm),
        }

        if version.is_some() {
            return Err(Error::Version);
        }

        if salt.is_empty() {
            return Err(Error::SaltInvalid);
        }

        // The trait passes the salt as raw bytes which may not be
        // representable in an MCF string; encode them with the crypt base64
        // alphabet first (the same convention used by RustCrypto's
        // `sha-crypt` crate). SHA-crypt truncates the salt at SALT_LEN_MAX
        // characters, so store exactly the effective salt.
        let mut encoded = encode_crypt_base64(salt);
        encoded.truncate(SALT_LEN_MAX);
        let salt: &[u8] = &encoded;

        // Assemble the `$6$[rounds=N$]salt` spec and defer to the crate's
        // reference-port core, keeping output bit-identical to the native
        // API (which likewise omits `rounds=` for the default of 5000).
        let rounds_custom = params.rounds != ROUNDS_DEFAULT;
        let mut spec = Vec::with_capacity(salt_spec_output_size(salt.len(), rounds_custom));
        spec.extend_from_slice(SHA512_SALT_PREFIX);
        if rounds_custom {
            spec.extend_from_slice(SHA512_ROUNDS_PREFIX);
            push_u32_as_ascii(params.rounds, &mut spec);
            spec.push(b'$');
        }
        spec.extend_from_slice(salt);

        // `hash_with_salt` zeroes the password copy before returning.
        let hash = hash_with_salt(Password::from_bytes(password.to_vec()), &spec);

        // The SHA-crypt core's output is always well-formed MCF.
        PasswordHash::new(hash).map_err(|_| Error::EncodingInvalid)
    }
}

impl PasswordHasher<PasswordHash> for Sha512Crypt {
    fn hash_password_with_salt(&self, password: &[u8], salt: &[u8]) -> Result<PasswordHash> {
        self.hash_password_customized(password, salt, None, None, self.params)
    }
}

impl PasswordVerifier<PasswordHash> for Sha512Crypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHash) -> Result<()> {
        self.verify_password(password, hash.as_password_hash_ref())
    }
}

impl PasswordVerifier<PasswordHashRef> for Sha512Crypt {
    fn verify_password(&self, password: &[u8], hash: &PasswordHashRef) -> Result<()> {
        if hash.id() != SHA512_CRYPT_ID {
            return Err(Error::Algorithm);
        }

        let mut fields = hash.fields();

        // The first field is either an explicit `rounds=N` params field
        // (digits only) or the salt itself.
        let mut salt = fields.next().ok_or(Error::EncodingInvalid)?;
        let mut rounds: Option<&str> = None;
        if let Some(rest) = salt.as_str().strip_prefix("rounds=") {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                rounds = Some(rest);
                salt = fields.next().ok_or(Error::EncodingInvalid)?;
            }
        }

        let expected = fields.next().ok_or(Error::EncodingInvalid)?;

        // Trailing fields are not part of the SHA512-crypt format.
        if fields.next().is_some() {
            return Err(Error::EncodingInvalid);
        }

        // Rebuild the salt spec exactly as found and recompute. The core
        // re-parses and clamps `rounds` itself, so non-normalized hashes
        // (e.g. `rounds=10`, which the spec clamps to 1000) verify against
        // their digest rather than failing on string form.
        let mut spec = Vec::with_capacity(salt_spec_output_size(
            salt.as_str().len().min(SALT_LEN_MAX),
            rounds.is_some(),
        ));
        spec.extend_from_slice(SHA512_SALT_PREFIX);
        if let Some(rounds) = rounds {
            spec.extend_from_slice(SHA512_ROUNDS_PREFIX);
            spec.extend_from_slice(rounds.as_bytes());
            spec.push(b'$');
        }
        spec.extend_from_slice(salt.as_str().as_bytes());

        // `hash_with_salt` zeroes the password copy before returning.
        let computed = hash_with_salt(Password::from_bytes(password.to_vec()), &spec);

        // Compare digest fields only: the recomputed string carries the
        // normalized (truncated) salt, while `hash` may store a longer one
        // that the algorithm truncates identically.
        let digest_start = computed.rfind('$').map_or(0, |i| i + 1);
        if crypto::constant_time_eq(
            &computed.as_bytes()[digest_start..],
            expected.as_str().as_bytes(),
        ) {
            Ok(())
        } else {
            Err(Error::PasswordInvalid)
        }
    }
}

impl PasswordVerifier<str> for Sha512Crypt {
    fn verify_password(&self, password: &[u8], hash: &str) -> Result<()> {
        let hash = PasswordHashRef::new(hash).map_err(|_| Error::EncodingInvalid)?;
        self.verify_password(password, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use crate::hash;

    #[test]
    fn hash_and_verify_round_trip() {
        let hasher = Sha512Crypt::default();
        let hash = hasher
            .hash_password_with_salt(b"hunter2", b"raw salt bytes")
            .unwrap();
        assert!(hash.as_str().starts_with("$6$"));
        // Default rounds omit the params field, matching the native API.
        assert!(!hash.as_str().contains("rounds="));

        hasher.verify_password(b"hunter2", &hash).unwrap();
        hasher.verify_password(b"hunter2", hash.as_str()).unwrap();
        assert_eq!(
            hasher.verify_password(b"wrong", &hash),
            Err(Error::PasswordInvalid)
        );
        assert_eq!(
            hasher.verify_password(b"wrong", hash.as_str()),
            Err(Error::PasswordInvalid)
        );
    }

    #[test]
    fn customized_hashing() {
        let params = Sha512CryptParams::new(10_000).unwrap();
        let hasher = Sha512Crypt::default();

        let h = hasher
            .hash_password_with_params(b"pw", b"salt", params)
            .unwrap();
        assert!(h.as_str().starts_with("$6$rounds=10000$"));
        hasher.verify_password(b"pw", &h).unwrap();

        // Explicit algorithm id "6" is accepted...
        hasher
            .hash_password_customized(b"pw", b"salt", Some("6"), None, params)
            .unwrap();
        // ...any other id is rejected, as is any version.
        assert_eq!(
            hasher.hash_password_customized(b"pw", b"salt", Some("5"), None, params),
            Err(Error::Algorithm)
        );
        assert_eq!(
            hasher.hash_password_customized(b"pw", b"salt", Some("sha512"), None, params),
            Err(Error::Algorithm)
        );
        assert_eq!(
            hasher.hash_password_customized(b"pw", b"salt", None, Some(1), params),
            Err(Error::Version)
        );
    }

    #[test]
    fn verifies_drepper_reference_hashes() {
        let hasher = Sha512Crypt::default();

        let h = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        hasher.verify_password(b"Hello world!", h).unwrap();
        assert_eq!(
            hasher.verify_password(b"wrong password", h),
            Err(Error::PasswordInvalid)
        );

        let h = "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.";
        hasher.verify_password(b"Hello world!", h).unwrap();

        // `rounds=10` was clamped to 1000 by the producer; verification
        // recomputes with the stored (already normalized) value.
        let h = "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.";
        hasher
            .verify_password(b"the minimum number is still observed", h)
            .unwrap();
    }

    #[test]
    fn verify_rejects_foreign_and_malformed_hashes() {
        let hasher = Sha512Crypt::default();
        // Well-formed MCF, but a different algorithm.
        assert_eq!(
            hasher.verify_password(b"pw", "$5$salt$hash"),
            Err(Error::Algorithm)
        );
        // Not MCF at all.
        assert_eq!(
            hasher.verify_password(b"pw", "not a hash"),
            Err(Error::EncodingInvalid)
        );
        // Missing digest field.
        assert_eq!(
            hasher.verify_password(b"pw", "$6$nosalt"),
            Err(Error::EncodingInvalid)
        );
        // Trailing field.
        assert_eq!(
            hasher.verify_password(b"pw", "$6$salt$hash$extra"),
            Err(Error::EncodingInvalid)
        );
    }

    #[test]
    fn verify_tolerates_oversized_salt_field() {
        // SHA-crypt truncates the salt at 16 characters. Some producers
        // store the untruncated salt; recomputation truncates identically,
        // so the digest still matches.
        let base =
            crate::hash_with_salt(Password::from("Hello world!"), b"$6$1234567890abcdef");
        let extended = base.replace("$6$1234567890abcdef$", "$6$1234567890abcdefXYZ$");
        Sha512Crypt::default()
            .verify_password(b"Hello world!", extended.as_str())
            .unwrap();
    }

    #[test]
    fn raw_salt_bytes_are_base64_encoded() {
        let hasher = Sha512Crypt::default();
        let h = hasher
            .hash_password_with_salt(b"pw", &[0xde, 0xad, 0xbe, 0xef])
            .unwrap();
        hasher.verify_password(b"pw", &h).unwrap();

        // The stored salt field uses only the crypt base64 alphabet and
        // never exceeds the 16-character SHA-crypt salt limit.
        let salt_field = h.as_str().split('$').nth(2).unwrap();
        assert!(salt_field.len() <= SALT_LEN_MAX);
        assert!(salt_field.bytes().all(|b| crate::B64_CHARS.contains(&b)));

        // Empty salts are rejected.
        assert_eq!(
            hasher.hash_password_with_salt(b"pw", b""),
            Err(Error::SaltInvalid)
        );
    }

    #[test]
    fn interops_with_native_api() {
        let hasher = Sha512Crypt::default();

        // Native output verifies through the trait implementation.
        for rounds in [None, Some(ROUNDS_DEFAULT), Some(100_000)] {
            let h = hash(Password::from("hunter2"), rounds);
            hasher.verify_password(b"hunter2", h.as_str()).unwrap();
        }

        // Trait output verifies through the native API, for both default
        // and custom rounds.
        for params in [Sha512CryptParams::DEFAULT, Sha512CryptParams::new(100_000).unwrap()] {
            let h = Sha512Crypt::new(params)
                .hash_password_with_salt(b"hunter2", b"pepper")
                .unwrap();
            assert_eq!(
                crate::verify(Password::from("hunter2"), h.as_str()),
                Ok(true)
            );
        }
    }

    #[test]
    fn params_validation_and_formatting() {
        assert_eq!(Sha512CryptParams::default().rounds(), 5_000);
        assert_eq!(Sha512CryptParams::DEFAULT.rounds(), 5_000);
        assert_eq!(Sha512CryptParams::new(1_000).unwrap().rounds(), 1_000);
        assert!(Sha512CryptParams::new(999).is_err());
        assert!(Sha512CryptParams::new(1_000_000_000).is_err());

        assert_eq!(Sha512CryptParams::default().to_string(), "rounds=5000");
        assert_eq!(
            "rounds=10000".parse::<Sha512CryptParams>().unwrap(),
            Sha512CryptParams::new(10_000).unwrap()
        );
        assert_eq!(
            "".parse::<Sha512CryptParams>().unwrap(),
            Sha512CryptParams::DEFAULT
        );
        assert!("nonsense".parse::<Sha512CryptParams>().is_err());
        assert!("rounds=abc".parse::<Sha512CryptParams>().is_err());

        let params = Sha512CryptParams::new(42_000).unwrap();
        let hasher = Sha512Crypt::from(params);
        assert_eq!(hasher.params(), params);
        assert_eq!(Sha512Crypt::DEFAULT, Sha512Crypt::default());
    }

    /// Regression vectors for [`encode_crypt_base64`], captured from
    /// base64ct's `Base64ShaCrypt` (the encoding used by RustCrypto's
    /// `sha-crypt` crate) and verified byte-identical over hundreds of
    /// pseudo-random inputs of every length 0..=32.
    #[test]
    fn crypt_base64_encoder_matches_reference() {
        assert_eq!(crate::encode_crypt_base64(b""), b"");
        assert_eq!(crate::encode_crypt_base64(b"f"), b"a/");
        assert_eq!(crate::encode_crypt_base64(b"fo"), b"ax4");
        assert_eq!(crate::encode_crypt_base64(b"foo"), b"axqP");
        assert_eq!(crate::encode_crypt_base64(b"foob"), b"axqPW/");
        assert_eq!(crate::encode_crypt_base64(b"fooba"), b"axqPW34");
        assert_eq!(crate::encode_crypt_base64(b"foobar"), b"axqPW3aQ");

        // Full-pipeline pin: raw salt bytes -> encoded salt (truncated at
        // the 16-character SHA-crypt limit) -> $6$ hash.
        let h = Sha512Crypt::default()
            .hash_password_with_salt(b"hunter2", b"raw salt bytes")
            .unwrap();
        assert_eq!(
            h.as_str(),
            "$6$m3qRUALMgF56WZ5R$yf0LQe6XA6TzObAJAYVtbfLybgkh9VuN8mPHFN4zgb36g4ZwZqCTiDBYZeOuX.cky5uePKTVcqlx54jWH.FnK/"
        );
    }
}
