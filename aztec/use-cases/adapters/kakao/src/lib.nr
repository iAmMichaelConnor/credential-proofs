//! Kakao Login adapter: a Kakao ID token (RS256) as an OIDC family input
//! (`uc_family_oidc::OidcProviderInput`). The login-link instance wraps it as
//! `OidcLink { input }`. use-cases.json declares account authorisation and
//! login link for this adapter, and the generator
//! refuses the others: the profile has no signed attribute (attribute gating),
//! and a Kakao `sub` is the opaque service-user id of the app; this repository
//! does not establish whether it is the same across apps (uniqueness).
//!
//! The token is verified by `kakao::verify_kakao_with_iat`: RS256 under the
//! supplied key, issuer `https://kauth.kakao.com`, audience, subject, nonce,
//! `exp > now` and `nbf <= now`. The supplied key and audience are not trusted
//! by themselves: they enter `OidcLogin.issuer` (`issuer_pin`), which the
//! use-case terms pin. It also requires exactly one signed unsigned-integer
//! `iat`, not after `now`, and the adapter reports it as `OidcLogin.issued_at`
//!.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use kakao::verify_kakao_with_iat;
use oidc::{JwtInput, TrustedRsaKey};
use std::meta::derive;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, rsa_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The Kakao Login scheme id.
pub global SCHEME_KAKAO: u32 = 25;

/// Poseidon2 of the issuer that the verifier requires.
pub global KAKAO_ISSUER: Field = comptime { poseidon2_hash_bytes("https://kauth.kakao.com".as_bytes()) };

/// A Kakao ID token with the key and client id it must verify
/// under. The subject is the token's `sub`; the verifier requires them to
/// be equal.
#[derive(Serialize, Deserialize)]
pub struct KakaoIdToken {
    /// The provider's RS256 modulus and Barrett parameters (2048-bit, 18 limbs).
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

impl KakaoIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        rsa_key_hash(self.modulus_limbs, self.redc_params_limbs)
    }

    /// The trust root that this input pins: key, issuer and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            KAKAO_ISSUER,
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for KakaoIdToken {
    let SCHEME: u32 = 25;

    /// The pinned key, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let result = verify_kakao_with_iat(
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
            subject: subject_id(KAKAO_ISSUER, bounded_bytes_hash(self.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for KakaoIdToken {}
