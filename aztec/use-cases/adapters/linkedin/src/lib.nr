//! LinkedIn adapter: a LinkedIn ID token (RS256, 4096-bit key) as an OIDC
//! family input (`uc_family_oidc::OidcProviderInput`). LinkedIn's published
//! ID-token claims have no nonce, so the token cannot carry a challenge: it
//! is bearer evidence. The login-link instance wraps it as
//! `OidcBearerLink { input }`, which labels the claim bearer and
//! `ALSO_IDP | ALSO_CLIENT_OPERATOR | ALSO_COPY_HOLDER`. use-cases.json
//! declares no use case for this adapter and only the login link as a bearer
//! use case (no account, no gate, no uniqueness).
//!
//! The token is verified by `linkedin::verify_linkedin_bearer_times`: RS256
//! under the supplied 4096-bit key, `typ` JWT, issuer
//! `https://www.linkedin.com`, audience, subject, `azp` (if present) equal to
//! the audience, `exp > now`, `iat <= now` and `nbf <= now`. The supplied key
//! and audience are not trusted by themselves: they enter `OidcLogin.issuer`
//! (`issuer_pin`), which the use-case terms pin. The library returns the
//! signed `iat`, so `OidcLogin.issued_at` is signed (`SignedIssueTime`):
//! `MAX_BEARER_AGE` applies to the real age of the token.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use linkedin::verify_linkedin_bearer_times;
use oidc::{JwtInput, TrustedRsa4096Key};
use std::meta::derive;
use uc_family_oidc::{bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, SignedIssueTime, subject_id};

mod tests;

/// The LinkedIn scheme id.
pub global SCHEME_LINKEDIN: u32 = 44;

/// Poseidon2 of the issuer that the verifier requires.
pub global LINKEDIN_ISSUER: Field = comptime { poseidon2_hash_bytes("https://www.linkedin.com".as_bytes()) };

/// A LinkedIn ID token with the key and client id it must verify under. The
/// subject is the token's `sub`; the verifier requires them to be equal.
#[derive(Serialize, Deserialize)]
pub struct LinkedInIdToken {
    /// LinkedIn's RS256 modulus and Barrett parameters (4096-bit, 35 limbs).
    pub modulus_limbs: [u128; 35],
    pub redc_params_limbs: [u128; 35],
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 256>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 256>,
    pub payload_b64: BoundedVec<u8, 2048>,
    pub signature_b64: BoundedVec<u8, 684>,
}

impl LinkedInIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        let mut limbs = [0; 70];
        for i in 0..35 {
            limbs[i] = self.modulus_limbs[i] as Field;
            limbs[35 + i] = self.redc_params_limbs[i] as Field;
        }
        poseidon2_hash(limbs)
    }

    /// The trust root that this input pins: key, issuer and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            LINKEDIN_ISSUER,
            bounded_bytes_hash(self.audience),
        )
    }
}

/// `verify_linkedin_bearer_times` returns the signed `iat`.
impl SignedIssueTime for LinkedInIdToken {}

impl OidcProviderInput for LinkedInIdToken {
    let SCHEME: u32 = 44;

    /// The pinned key, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    /// LinkedIn tokens carry no nonce, so only the empty nonce is accepted.
    /// A wrapper that asks the token to carry a challenge (`OidcLink`,
    /// `OidcAccount`) therefore fails instead of claiming a binding.
    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        assert(nonce.len() == 0, "LinkedIn tokens carry no nonce");
        let times = verify_linkedin_bearer_times(
            JwtInput::<256, 2048, 684> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.audience,
            self.subject,
            now,
            TrustedRsa4096Key { modulus_limbs: self.modulus_limbs, redc_params_limbs: self.redc_params_limbs },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(LINKEDIN_ISSUER, bounded_bytes_hash(self.subject)),
            expiry: times.expiry,
            issued_at: times.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}
