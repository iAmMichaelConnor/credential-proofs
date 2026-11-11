//! LINE Login adapter: a LINE ID token (ES256, native app, SDK or LIFF) as an
//! OIDC family input (`uc_family_oidc::OidcProviderInput`). The login-link
//! instance wraps it as `OidcLink { input }`. use-cases.json declares account
//! authorisation and login link for this adapter,
//! and the generator refuses the others: the profile has no signed attribute
//! (attribute gating), and a LINE user id is one LINE account per provider,
//! not one person (uniqueness).
//!
//! The token is verified by `line::verify_line_with_iat`: ES256 under the
//! supplied P-256 key, issuer `https://access.line.me`, a decimal channel id
//! as the audience, subject, nonce, `exp > now`, `nbf <= now` and exactly one
//! signed unsigned-integer `iat`, not after `now`, which the adapter reports
//! as `OidcLogin.issued_at`. Web-login HS256 tokens are not accepted. The
//! supplied key and channel id are not trusted by themselves: they enter
//! `OidcLogin.issuer` (`issuer_pin`), which the use-case terms pin.
//!
//! ES256 accepts both `s` and `n - s`, so one login has two valid
//! signatures. A login link does not depend on signature uniqueness: its
//! nullifier is per subject, not per token.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use line::verify_line_with_iat;
use oidc::{JwtInput, TrustedP256Key};
use std::meta::derive;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, p256_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The LINE scheme id.
pub global SCHEME_LINE: u32 = 22;

/// Poseidon2 of the issuer that the verifier requires.
pub global LINE_ISSUER: Field = comptime { poseidon2_hash_bytes("https://access.line.me".as_bytes()) };

/// A LINE ID token with the key and channel id it must verify under. The
/// subject is the token's `sub`; the verifier requires them to be equal.
#[derive(Serialize, Deserialize)]
pub struct LineIdToken {
    /// LINE's P-256 signing key (uncompressed coordinates, big-endian).
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    /// The channel id (decimal) that the token must name as `aud`.
    pub audience: BoundedVec<u8, 32>,
    /// The token's `sub` (the LINE user id).
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 192>,
    pub payload_b64: BoundedVec<u8, 1024>,
    pub signature_b64: BoundedVec<u8, 86>,
}

impl LineIdToken {
    /// The trust root that this input pins: key, issuer and channel id.
    pub fn issuer(self) -> Field {
        issuer_pin(
            p256_key_hash(self.public_key_x, self.public_key_y),
            LINE_ISSUER,
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for LineIdToken {
    let SCHEME: u32 = 22;

    /// The pinned key, channel id and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let result = verify_line_with_iat(
            JwtInput::<192, 1024, 86> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.audience,
            self.subject,
            nonce,
            now,
            TrustedP256Key { public_key_x: self.public_key_x, public_key_y: self.public_key_y },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(LINE_ISSUER, bounded_bytes_hash(self.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for LineIdToken {}
