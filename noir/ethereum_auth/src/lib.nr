//! Ethereum EIP-191 authentication and secret-key knowledge checks.
//!
//! - `eip191::verify_personal_sign`: a 64-byte secp256k1 `r || s` over the
//!   `personal_sign` digest of a bounded message (decimal length up to ten
//!   digits), with the supplied public key bound to `expected_address`. No key
//!   recovery from a 65-byte signature.
//! - `siwe`: the exact no-statement EIP-4361 profile (EIP-55 address, domain,
//!   URI, decimal chain ID, nonce, issued-at, expiration) with UTC calendar
//!   validation and `issued_at <= current_time < expiration_time`.
//! - `secret_key::assert_secret_key_for_address`: knowledge of a canonical
//!   nonzero scalar whose generator multiple maps to `expected_address`; it
//!   signs nothing and establishes no account policy.
//!
//! Caller obligations: the expected address, domain, URI, chain, nonce and
//! `current_time` come from trusted state, and the nonce is consumed. EIP-191
//! alone is not SIWE. `personal_sign` over a raw digest is blind signing: the
//! wallet shows opaque hex, which a phishing page can present as a "login", and
//! the relation has no deadline. A consumer that signs a digest must tag it with
//! a domain and a deadline it enforces; prefer `siwe`, which shows a readable
//! message with an expiration time.
pub mod eip191;
pub mod siwe;
pub mod secret_key;
mod benchmarks;
mod known_answer_tests;
