//! FranceConnect+ adapter: the inner signed ID token of FranceConnect+
//! (ES256) as an OIDC family input (`uc_family_oidc::OidcProviderInput`).
//! The login-link instance wraps it as `OidcLink { input }`. use-cases.json
//! declares account authorisation, login link and attribute gating. The
//! additive FranceConnectAssuranceToken reports the actual signed eIDAS rank;
//! FranceConnectIdToken itself reports no attribute. Neither establishes a
//! one-per-person subject.
//!
//! The token is verified by `franceconnect::verify_franceconnect_with_iat`:
//! ES256 under the supplied P-256 key, the production issuer
//! `https://auth.franceconnect.gouv.fr/api/v2` or the integration issuer,
//! audience, subject, nonce, `exp > now`, `nbf <= now`, a signed root `acr`
//! of `eidas2` or `eidas3` at least `minimum_acr` (2 or 3), and exactly one
//! signed unsigned-integer `iat`, not after `now`, which the adapter reports
//! as `OidcLogin.issued_at`. The supplied key, environment, minimum level and
//! audience are not trusted by themselves: they enter `OidcLogin.issuer`
//! (`issuer_pin`), which the use-case terms pin.
//!
//! FranceConnect+ encrypts the ID token (JWE); the host decrypts it and the
//! circuit sees the inner signed token. The client operator that decrypts it
//! can also choose the nonce (`ALSO_CLIENT_OPERATOR`, set by the family
//! wrapper). ES256 accepts both `s` and `n - s`; a login link does not
//! depend on signature uniqueness, because its nullifier is per subject.
use aztec::protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}};
use franceconnect::{verify_franceconnect_with_iat, verify_franceconnect_with_iat_and_assurance};
use oidc::{JwtInput, TrustedP256Key};
use std::meta::derive;
use uc_attribute_gate::KIND_ASSURANCE_LEVEL;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, p256_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The FranceConnect+ scheme id.
pub global SCHEME_FRANCECONNECT: u32 = 26;

/// Poseidon2 of the production and integration issuers that the verifier requires.
pub global FRANCECONNECT_ISSUER: Field =
    comptime { poseidon2_hash_bytes("https://auth.franceconnect.gouv.fr/api/v2".as_bytes()) };
pub global FRANCECONNECT_INTEGRATION_ISSUER: Field = comptime {
    poseidon2_hash_bytes(
        "https://auth.integ01.dev-franceconnect.fr/api/v2".as_bytes(),
    )
};

/// A FranceConnect+ inner ID token with the key, environment, minimum eIDAS
/// level and client id it must verify under. The subject is the token's
/// `sub`; the verifier requires them to be equal.
#[derive(Serialize, Deserialize)]
pub struct FranceConnectIdToken {
    /// The FranceConnect+ P-256 signing key (uncompressed coordinates).
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    /// True for the integration issuer.
    pub integration: bool,
    /// Minimum signed `acr`: 2 (`eidas2`) or 3 (`eidas3`).
    pub minimum_acr: u8,
    /// The client id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub`.
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 192>,
    pub payload_b64: BoundedVec<u8, 1024>,
    pub signature_b64: BoundedVec<u8, 86>,
}

impl FranceConnectIdToken {
    /// The hash of the issuer of the selected environment.
    pub fn issuer_name(self) -> Field {
        if self.integration {
            FRANCECONNECT_INTEGRATION_ISSUER
        } else {
            FRANCECONNECT_ISSUER
        }
    }

    /// The trust root that this input pins: key, issuer, minimum level and
    /// audience. The minimum level is part of the pin, so a prover cannot
    /// lower it.
    pub fn issuer(self) -> Field {
        issuer_pin(
            p256_key_hash(self.public_key_x, self.public_key_y),
            poseidon2_hash([self.issuer_name(), self.minimum_acr as Field]),
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for FranceConnectIdToken {
    let SCHEME: u32 = 26;

    /// The pinned key, environment, minimum level, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let result = verify_franceconnect_with_iat(
            JwtInput::<192, 1024, 86> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.audience,
            self.subject,
            nonce,
            now,
            self.integration,
            self.minimum_acr,
            TrustedP256Key { public_key_x: self.public_key_x, public_key_y: self.public_key_y },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(self.issuer_name(), bounded_bytes_hash(self.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: 0,
            attribute: 0,
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for FranceConnectIdToken {}

/// FC+ token reporting its actual signed assurance. The configured minimum is
/// still part of the issuer pin and the verification floor, not the attribute.
#[derive(Serialize, Deserialize)]
pub struct FranceConnectAssuranceToken {
    pub token: FranceConnectIdToken,
}

impl SignedIssueTime for FranceConnectAssuranceToken {}

impl FranceConnectAssuranceToken {
    pub fn issuer(self) -> Field {
        self.token.issuer()
    }
}

impl OidcProviderInput for FranceConnectAssuranceToken {
    let SCHEME: u32 = 26;

    fn policy_hash(self) -> Field {
        self.token.policy_hash()
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let token = self.token;
        let (result, assurance) = verify_franceconnect_with_iat_and_assurance(
            JwtInput::<192, 1024, 86> {
                header_b64: token.header_b64,
                payload_b64: token.payload_b64,
                signature_b64: token.signature_b64,
            },
            token.audience,
            token.subject,
            nonce,
            now,
            token.integration,
            token.minimum_acr,
            TrustedP256Key { public_key_x: token.public_key_x, public_key_y: token.public_key_y },
        );
        OidcLogin {
            issuer: token.issuer(),
            subject: subject_id(token.issuer_name(), bounded_bytes_hash(token.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: KIND_ASSURANCE_LEVEL,
            attribute: assurance as Field,
        }
    }
}
