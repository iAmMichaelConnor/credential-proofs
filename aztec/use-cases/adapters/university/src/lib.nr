//! University (CILogon) adapter: a CILogon ID token (RS256) that names a
//! trusted campus identity provider, as an OIDC family input
//! (`uc_family_oidc::OidcProviderInput`). The login-link instance wraps it as
//! `OidcLink { input }`. use-cases.json declares account authorisation, login
//! link and attribute gating for this adapter. Uniqueness is refused: one
//! person can hold several campus and CILogon identities.
//!
//! `UniversityIdToken` reports no attribute. The attribute-gating instance
//! takes `UniversityAffiliationToken` (use-cases.json `types`), the same
//! token with one affiliation entry, and wraps it as `OidcAttribute { input }`
//!. It is verified by `university::verify_cilogon_with_affiliation`:
//! the checks below, and that the entry is one element of the signed
//! semicolon-delimited `affiliation` claim (exact bytes, no substring). The
//! adapter reports the entry as the `KIND_AFFILIATION` attribute
//! (`affiliation_attribute`). The prover picks which signed entry to present.
//! The value is as asserted by the campus identity provider through CILogon:
//! it may be cached and does not prove current enrolment.
//!
//! The token is verified by `university::verify_cilogon`: RS256 under the
//! supplied key, issuer `https://cilogon.org`, audience, subject, nonce, a
//! signed `idp` equal to the supplied campus identity provider, `exp > now`,
//! `iat <= now` and `nbf <= now`. The supplied key, campus identity provider
//! and audience are not trusted by themselves: they enter `OidcLogin.issuer`
//! (`issuer_pin`), which the use-case terms pin. The library returns the
//! signed `iat`, so `OidcLogin.issued_at` is signed (`SignedIssueTime`).
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use oidc::{JwtInput, literal_vec, TrustedRsaKey};
use std::meta::derive;
use uc_attribute_gate::KIND_AFFILIATION;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, rsa_key_hash, SignedIssueTime, subject_id,
};
use university::{AuthPolicy, verify_cilogon, verify_cilogon_with_affiliation};

mod tests;

/// The university scheme id.
pub global SCHEME_UNIVERSITY: u32 = 27;

/// Poseidon2 of the CILogon issuer that the verifier requires.
pub global CILOGON_ISSUER: Field = comptime { poseidon2_hash_bytes("https://cilogon.org".as_bytes()) };

/// A CILogon ID token with the key, campus identity provider and client id
/// it must verify under. The subject is the token's `sub`; the verifier
/// requires them to be equal.
#[derive(Serialize, Deserialize)]
pub struct UniversityIdToken {
    /// CILogon's RS256 modulus and Barrett parameters (2048-bit, 18 limbs).
    pub modulus_limbs: [u128; 18],
    pub redc_params_limbs: [u128; 18],
    /// The campus identity provider (SAML entityID) that the signed `idp`
    /// claim must name.
    pub institutional_idp: BoundedVec<u8, 256>,
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 256>,
    pub payload_b64: BoundedVec<u8, 2048>,
    pub signature_b64: BoundedVec<u8, 344>,
}

impl UniversityIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        rsa_key_hash(self.modulus_limbs, self.redc_params_limbs)
    }

    /// The trust root that this input pins: key, issuer, campus identity
    /// provider and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            poseidon2_hash([CILOGON_ISSUER, bounded_bytes_hash(self.institutional_idp)]),
            bounded_bytes_hash(self.audience),
        )
    }
}

/// `verify_cilogon` returns the signed `iat`.
impl SignedIssueTime for UniversityIdToken {}

impl OidcProviderInput for UniversityIdToken {
    let SCHEME: u32 = 27;

    /// The pinned key, campus identity provider, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let claims = verify_cilogon(
            JwtInput::<256, 2048, 344> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            TrustedRsaKey { modulus_limbs: self.modulus_limbs, redc_params_limbs: self.redc_params_limbs },
            AuthPolicy {
                issuer: literal_vec("https://cilogon.org"),
                audience: self.audience,
                subject: self.subject,
                institutional_idp: self.institutional_idp,
            },
            nonce,
            now,
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(CILOGON_ISSUER, bounded_bytes_hash(self.subject)),
            expiry: claims.expiry,
            issued_at: claims.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}

/// The `KIND_AFFILIATION` attribute value of an affiliation entry, for
/// example `student@example.edu`: `bounded_bytes_hash` of the entry at the
/// input capacity of 128 bytes (the hash depends on the capacity).
pub fn affiliation_attribute(affiliation: BoundedVec<u8, 128>) -> Field {
    bounded_bytes_hash(affiliation)
}

/// A CILogon ID token (as `UniversityIdToken`) with one entry of its signed
/// `affiliation` claim, for attribute gating.
#[derive(Serialize, Deserialize)]
pub struct UniversityAffiliationToken {
    pub token: UniversityIdToken,
    /// One exact entry of the signed semicolon-delimited `affiliation` claim
    /// (an eduPersonScopedAffiliation value such as `student@example.edu`).
    /// It is not part of the pinned issuer: it is the reported attribute.
    pub affiliation: BoundedVec<u8, 128>,
}

/// `verify_cilogon_with_affiliation` returns the signed `iat`.
impl SignedIssueTime for UniversityAffiliationToken {}

impl OidcProviderInput for UniversityAffiliationToken {
    let SCHEME: u32 = 27;

    /// As `UniversityIdToken`: the affiliation is not part of the policy.
    fn policy_hash(self) -> Field {
        self.token.policy_hash()
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let token = self.token;
        let claims = verify_cilogon_with_affiliation(
            JwtInput::<256, 2048, 344> {
                header_b64: token.header_b64,
                payload_b64: token.payload_b64,
                signature_b64: token.signature_b64,
            },
            TrustedRsaKey { modulus_limbs: token.modulus_limbs, redc_params_limbs: token.redc_params_limbs },
            AuthPolicy {
                issuer: literal_vec("https://cilogon.org"),
                audience: token.audience,
                subject: token.subject,
                institutional_idp: token.institutional_idp,
            },
            nonce,
            now,
            self.affiliation,
        );
        OidcLogin {
            issuer: token.issuer(),
            subject: subject_id(CILOGON_ISSUER, bounded_bytes_hash(token.subject)),
            expiry: claims.expiry,
            issued_at: claims.issued_at,
            attribute_kind: KIND_AFFILIATION,
            attribute: affiliation_attribute(self.affiliation),
        }
    }
}
