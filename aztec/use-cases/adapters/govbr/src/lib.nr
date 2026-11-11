//! gov.br adapter: a gov.br ID token (RS256) as an OIDC family input
//! (`uc_family_oidc::OidcProviderInput`). The login-link instance wraps it as
//! `OidcLink { input }`; the attribute-gating instance wraps it as
//! `OidcAttribute { input }` and gates on the signed assurance rank.
//! use-cases.json declares account authorisation, login link and attribute
//! gating for this adapter. A one-per-CPF uniqueness instance needs a
//! confirmed person subject; this adapter does not claim one.
//!
//! The token is verified by `govbr::verify_govbr_with_assurance`: RS256 under the
//! supplied key, issuer `https://sso.acesso.gov.br/` (or the staging issuer),
//! audience, subject, nonce, `exp > now`, `nbf <= now` and a signed
//! `reliability_info.level` at least `minimum_level`. The supplied key,
//! environment, minimum level and audience are not trusted by themselves: they
//! enter `OidcLogin.issuer` (`issuer_pin`), which the use-case terms pin. It
//! also requires exactly one signed unsigned-integer `iat`, not after `now`,
//! and the adapter reports it as `OidcLogin.issued_at`. It returns the
//! signed assurance rank (1 bronze, 2 silver, 3 gold), which the adapter
//! reports as the `KIND_ASSURANCE_LEVEL` attribute. The rank is at
//! least the pinned `minimum_level`; gate terms compare it with their own
//! threshold.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use govbr::verify_govbr_with_assurance;
use oidc::{JwtInput, TrustedRsaKey};
use std::meta::derive;
use uc_attribute_gate::KIND_ASSURANCE_LEVEL;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, rsa_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The gov.br scheme id.
pub global SCHEME_GOVBR: u32 = 23;

/// Poseidon2 of the production and staging issuers that the verifier requires.
pub global GOVBR_ISSUER: Field = comptime { poseidon2_hash_bytes("https://sso.acesso.gov.br/".as_bytes()) };
pub global GOVBR_STAGING_ISSUER: Field =
    comptime { poseidon2_hash_bytes("https://sso.staging.acesso.gov.br/".as_bytes()) };

/// A gov.br ID token with the key, environment, minimum assurance and client
/// id it must verify under. The subject is the token's `sub` (the CPF); the
/// verifier requires them to be equal byte for byte.
#[derive(Serialize, Deserialize)]
pub struct GovbrIdToken {
    /// gov.br's RS256 modulus and Barrett parameters (2048-bit, 18 limbs).
    pub modulus_limbs: [u128; 18],
    pub redc_params_limbs: [u128; 18],
    /// True for the staging issuer.
    pub staging: bool,
    /// Minimum signed assurance: 1 bronze, 2 silver, 3 gold.
    pub minimum_level: u8,
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 128>,
    pub payload_b64: BoundedVec<u8, 2048>,
    pub signature_b64: BoundedVec<u8, 344>,
}

impl GovbrIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        rsa_key_hash(self.modulus_limbs, self.redc_params_limbs)
    }

    /// The hash of the issuer of the selected environment.
    pub fn issuer_name(self) -> Field {
        if self.staging {
            GOVBR_STAGING_ISSUER
        } else {
            GOVBR_ISSUER
        }
    }

    /// The trust root that this input pins: key, issuer, minimum assurance
    /// and audience. The minimum level is part of the pin, so a prover cannot
    /// lower it.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            poseidon2_hash([self.issuer_name(), self.minimum_level as Field]),
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for GovbrIdToken {
    let SCHEME: u32 = 23;

    /// The pinned key, environment, minimum level, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let login = verify_govbr_with_assurance(
            JwtInput::<128, 2048, 344> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.audience,
            self.subject,
            nonce,
            now,
            self.staging,
            self.minimum_level,
            TrustedRsaKey { modulus_limbs: self.modulus_limbs, redc_params_limbs: self.redc_params_limbs },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(self.issuer_name(), bounded_bytes_hash(self.subject)),
            expiry: login.claims.claims.expiry,
            issued_at: login.claims.issued_at,
            attribute_kind: KIND_ASSURANCE_LEVEL,
            attribute: login.assurance as Field,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for GovbrIdToken {}
