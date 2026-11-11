//! Google Sign-In adapter: a Google ID token (RS256) as an OIDC family input
//! (`uc_family_oidc::OidcProviderInput`). The use cases wrap it:
//! `OidcLink { input }` for a login link and `OidcAccount { input }` for an
//! account. use-cases.json declares only these two use cases for Google, and
//! the generator refuses the others: the profile has no signed attribute
//! (attribute gating), and a Google `sub` is one account, not one person,
//! and is the same for every client, not pairwise (uniqueness).
//!
//! The token is verified by `oidc::verify_google_with_iat` (noir/oidc):
//! RS256 under the supplied key, issuer `https://accounts.google.com` (or the
//! legacy `accounts.google.com`), audience, subject, nonce, `exp > now` and
//! `nbf <= now`. The supplied key and audience are not trusted by themselves:
//! they enter `OidcLogin.issuer` (`issuer_pin`), which the use-case terms pin.
//! It also requires exactly one signed unsigned-integer `iat`, not after `now`,
//! and the adapter reports it as `OidcLogin.issued_at`.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use oidc::{JwtInput, TrustedRsaKey, verify_google_with_iat};
use std::meta::derive;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, rsa_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The Google scheme id.
pub global SCHEME_GOOGLE: u32 = 2;

/// Poseidon2 of the canonical issuer, for both accepted issuer spellings.
pub global GOOGLE_ISSUER: Field = comptime { poseidon2_hash_bytes("https://accounts.google.com".as_bytes()) };

/// A Google ID token with the key and client id it must verify under. The
/// subject is the token's `sub`; the verifier requires them to be equal.
#[derive(Serialize, Deserialize)]
pub struct GoogleIdToken {
    /// Google's RS256 modulus and Barrett parameters (2048-bit, 18 limbs).
    pub modulus_limbs: [u128; 18],
    pub redc_params_limbs: [u128; 18],
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 128>,
    pub payload_b64: BoundedVec<u8, 1024>,
    pub signature_b64: BoundedVec<u8, 344>,
}

impl GoogleIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        rsa_key_hash(self.modulus_limbs, self.redc_params_limbs)
    }

    /// The trust root that this input pins: key, issuer and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            GOOGLE_ISSUER,
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for GoogleIdToken {
    let SCHEME: u32 = 2;

    /// The pinned key, audience and subject (an account built from this input).
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let result = verify_google_with_iat(
            JwtInput::<128, 1024, 344> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.audience,
            self.subject,
            nonce,
            now,
            TrustedRsaKey { modulus_limbs: self.modulus_limbs, redc_params_limbs: self.redc_params_limbs },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(GOOGLE_ISSUER, bounded_bytes_hash(self.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for GoogleIdToken {}
