//! Singpass adapter: a Singpass FAPI inner ID token (ES256) as an OIDC
//! family input (`uc_family_oidc::OidcProviderInput`). use-cases.json
//! declares attribute gating and login link for it: the attribute-gating
//! instance wraps it as `OidcAttribute { input }` and gates on the signed
//! authentication assurance level (`acr`, `urn:singpass:authentication:loa:1`
//! to `3`); the login-link instance wraps it as `OidcLink { input }`.
//! The Singpass account keeps its own in-crate input.
//!
//! The token is verified by `singpass_auth::authorise`: ES256 under the
//! supplied P-256 key, issuer `https://id.singpass.gov.sg/fapi` (environment
//! 0) or `https://stg-id.singpass.gov.sg/fapi` (environment 1), audience,
//! subject, nonce, `exp > now`, `nbf <= now`, `iat <= now`, `sub_type`
//! `user`, no delegated `act`, and an assurance of at least 2 in production
//! (at least 1 in staging). The library returns the signed `iat`, `exp` and
//! assurance; the adapter reports the signed `iat` (`SignedIssueTime`). The supplied key, environment and audience are
//! not trusted by
//! themselves: they enter `OidcLogin.issuer` (`issuer_pin`), which the terms
//! pin.
//!
//! Encrypted transport (JWE) is decrypted on the host; the circuit sees the
//! inner signed token. The client operator that decrypts it can also choose
//! the nonce (`ALSO_CLIENT_OPERATOR`, set by the family wrapper).
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use oidc::{JwtInput, TrustedP256Key};
use singpass_auth::{authorise, AuthPolicy};
use std::meta::derive;
use uc_attribute_gate::KIND_ASSURANCE_LEVEL;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, p256_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The Singpass scheme id.
pub global SCHEME_SINGPASS: u32 = 30;

pub global SINGPASS_ISSUER: Field = comptime { poseidon2_hash_bytes("https://id.singpass.gov.sg/fapi".as_bytes()) };
pub global SINGPASS_STAGING_ISSUER: Field =
    comptime { poseidon2_hash_bytes("https://stg-id.singpass.gov.sg/fapi".as_bytes()) };

/// Environments (`SingpassIdToken.environment`), as `singpass_auth` numbers them.
pub global PRODUCTION: u8 = 0;
pub global STAGING: u8 = 1;

/// A Singpass ID token with the key, environment and client id it must
/// verify under. The subject is the token's `sub`; the verifier requires
/// them to be equal.
#[derive(Serialize, Deserialize)]
pub struct SingpassIdToken {
    /// Singpass's P-256 signing key (uncompressed coordinates).
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    /// `PRODUCTION` or `STAGING`; it fixes the issuer.
    pub environment: u8,
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 256>,
    pub payload_b64: BoundedVec<u8, 1024>,
    pub signature_b64: BoundedVec<u8, 86>,
}

/// Poseidon2 of the issuer string of an environment.
pub fn issuer_name(environment: u8) -> Field {
    assert(environment <= STAGING, "Unknown Singpass environment");
    if environment == PRODUCTION {
        SINGPASS_ISSUER
    } else {
        SINGPASS_STAGING_ISSUER
    }
}

impl SingpassIdToken {
    /// The trust root that this input pins: key, environment and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            p256_key_hash(self.public_key_x, self.public_key_y),
            issuer_name(self.environment),
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for SingpassIdToken {
    let SCHEME: u32 = 30;

    /// The pinned key, environment, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let claims = authorise(
            JwtInput::<256, 1024, 86> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            TrustedP256Key { public_key_x: self.public_key_x, public_key_y: self.public_key_y },
            AuthPolicy {
                audience: self.audience,
                subject: self.subject,
                environment: self.environment,
                // The library's floor: MFA (level 2) in production. The gate's
                // terms then compare the reported level with their threshold.
                minimum_assurance: if self.environment == PRODUCTION { 2 } else { 1 },
            },
            nonce,
            now,
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(
                issuer_name(self.environment),
                bounded_bytes_hash(self.subject),
            ),
            expiry: claims.expiry,
            issued_at: claims.issued_at,
            attribute_kind: KIND_ASSURANCE_LEVEL,
            attribute: claims.assurance as Field,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`, which
/// `singpass_auth::authorise` parses and checks (`iat <= now`).
impl SignedIssueTime for SingpassIdToken {}
