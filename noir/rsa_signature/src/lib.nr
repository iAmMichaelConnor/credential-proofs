//! Shared RSA PKCS1v1.5/SHA256 verification; no DKIM parsing.
//!
//! `RSAPubkey<9>`, `<18>` and `<35>` verify RSA-1024, 2048 and 4096 PKCS#1 v1.5
//! signatures with exponent 65537 over little-endian 120-bit limbs:
//! `verify_rsa_sha256_pkcs1v15(message, signature)` hashes the exact bytes and
//! returns the digest (`verify_dkim_signature` is the same function under its
//! zk-email name, not a DKIM-envelope validator); the digest forms
//! (`verify_digest_sha256_pkcs1v15`, `assert_valid_sha256_digest`,
//! `assert_valid_sha512_digest`) need a digest the caller constrained to its
//! message. `modulus_commitment()` (= `hash()[0]`, zk-email `poseidon_large`)
//! is the key commitment.
//!
//! Security preconditions:
//! - Accepted signatures lie in [1, n - 1]: `validate_in_field` allows
//!   `signature = n`, which then fails the padding equation.
//! - The Barrett `redc` limbs are range checked but not constrained to the
//!   reciprocal: never use `hash()[1]`, or the pair, as a key identifier,
//!   registry or denylist entry, or nullifier input; keep `redc` private.
//! - `RSAPubkey::new` does not check that the modulus is odd or full length. A
//!   caller taking a key in limb form calls `assert_rsa_modulus_shape` or
//!   compares `modulus_commitment()` with an enrolled value.
//! - The key comes from the caller's trust anchor; this package parses no email,
//!   HTTP or certificate data.
mod signature;
pub mod hash;
pub use signature::RSAPubkey;
pub global RSA_EXPONENT: u32 = 65537;
pub global KEY_LIMBS_1024: u32 = 9;
pub global KEY_LIMBS_2048: u32 = 18;

mod api_tests;
mod encoding;
pub use encoding::{assert_rsa_modulus_shape, rsa_bytes_to_limbs, rsa_modulus_bytes};
mod sha512_tests;
