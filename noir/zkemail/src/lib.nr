//! DKIM email verification adapted from zkemail.nr v2.0.0 (see NOTICE), using
//! `rsa_signature` for the RSA relation.
//!
//! - `dkim::RSAPubkey`: the shared RSA-1024/2048 key; `verify_dkim_signature`
//!   checks PKCS#1 v1.5 over the canonicalized signed header, and `hash()` is
//!   [modulus commitment (the only key identifier), Barrett hint hash (never a
//!   key identifier)].
//! - `headers::body_hash::get_body_hash`: the `bh=` of the final signed
//!   DKIM-Signature field (field capped at `MAX_DKIM_HEADER_FIELD_LENGTH`; use
//!   `get_body_hash_with_field_cap` for longer fields).
//! - `headers::email_address::get_email_address`: one mailbox from a signed
//!   header field (`parse_email_address` alone does not pin the span).
//! - `partial_hash`: low-level SHA-256 continuation; it cannot authenticate an
//!   external SHA state.
//!
//! The consumer compares output 0 with a trusted DKIM key commitment for the
//! intended domain, selector and validity period, binds the selected header
//! occurrence to DKIM's signed-header selection, and supplies its own message
//! template, challenge, freshness and replay rules. Arithmetic preconditions and
//! trust limits: `docs/zkemail.md`.
pub mod dkim;
pub mod headers;
pub mod masking;
pub mod partial_hash;
pub mod remove_soft_line_breaks;
mod tests;

pub global KEY_LIMBS_1024: u32 = 9;
pub global KEY_LIMBS_2048: u32 = 18;
pub global BODY_HASH_BASE64_LENGTH: u32 = 44;
pub global CR: u8 = 0x0D;
pub global LF: u8 = 0x0A;
// Default cap of get_body_hash on the canonicalized DKIM-Signature field
// ("dkim-signature:" through the empty b= value), in bytes. Longer fields
// need headers::body_hash::get_body_hash_with_field_cap.
pub global MAX_DKIM_HEADER_FIELD_LENGTH: u32 = 300;
pub global MAX_EMAIL_ADDRESS_LENGTH: u32 = 320; // derived via (https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1.1)

pub struct Sequence {
    pub index: u32,
    pub length: u32,
}

impl Sequence {
    pub fn end_index(self) -> u32 {
        self.index + self.length
    }
}
// Supported mailbox alphabet (kept compatible with js/src/utils:
// makeAllowableEmailCharsTable):
// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-@" = 1
// "<: " = 2; ">(\r\n" = 3. This is a deliberately bounded profile, not a
// complete RFC 5322 parser. In particular, '+' remains unsupported.
pub global EMAIL_ADDRESS_CHAR_TABLE: [u8; 123] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 2, 0, 3, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];
mod benchmarks;
mod known_answer_tests;
