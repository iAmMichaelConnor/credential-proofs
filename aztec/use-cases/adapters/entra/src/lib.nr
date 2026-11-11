//! Microsoft Entra ID adapter: an Entra v2.0 ID token (RS256) as an OIDC
//! family input (`uc_family_oidc::OidcProviderInput`). The login-link
//! instance wraps it as `OidcLink { input }`; the attribute-gating instance
//! wraps it as `OidcAttribute { input }` and gates on the tenant.
//! use-cases.json declares account authorisation, login link and attribute
//! gating for this adapter. Uniqueness is refused: Entra accounts are
//! workforce accounts, and the `sub` is pairwise per application, not one per
//! person.
//!
//! The token is verified by `entra::verify_entra_with_iat`: RS256 under the
//! supplied key, issuer `https://login.microsoftonline.com/{tenant}/v2.0` for
//! the supplied canonical tenant GUID, audience, subject, nonce, `exp > now`
//! and `nbf <= now`. The supplied key, tenant and audience are not trusted by
//! themselves: they enter `OidcLogin.issuer` (`issuer_pin`), which the use-case
//! terms pin. It also requires exactly one signed unsigned-integer `iat`, not
//! after `now`, and the adapter reports it as `OidcLogin.issued_at`.
//!
//! The attribute is the tenant (`KIND_TENANT`): `tenant_attribute(tenant)`,
//! the hash of the exact signed issuer string, which the library requires to
//! name the supplied tenant. The library returns no separate tenant value:
//! the exact issuer match fixes it. The same hash is also in
//! `OidcLogin.issuer`, so terms that pin the issuer already pin the tenant;
//! the attribute lets the terms state the tenant as the gated value. The
//! issuer tenant is the directory that signed the login, which for a B2B
//! guest account is the resource tenant, not the user's home organisation.
use aztec::protocol::{hash::poseidon2_hash, traits::{Deserialize, Serialize}};
use entra::{tenant_issuer, verify_entra_with_iat};
use oidc::{JwtInput, TrustedRsaKey};
use std::meta::derive;
use uc_attribute_gate::KIND_TENANT;
use uc_family_oidc::{
    bounded_bytes_hash, issuer_pin, OidcLogin, OidcProviderInput, rsa_key_hash, SignedIssueTime, subject_id,
};

mod tests;

/// The Entra scheme id.
pub global SCHEME_ENTRA: u32 = 13;

/// The `KIND_TENANT` attribute value of a tenant: Poseidon2 of its issuer
/// string `https://login.microsoftonline.com/{tenant}/v2.0`
/// (`bounded_bytes_hash`). It rejects a tenant that is not a canonical
/// lowercase GUID.
pub fn tenant_attribute(tenant: [u8; 36]) -> Field {
    bounded_bytes_hash(tenant_issuer(tenant))
}

/// An Entra ID token with the key, tenant and client id it must verify
/// under. The subject is the token's `sub`; the verifier requires them to be
/// equal.
#[derive(Serialize, Deserialize)]
pub struct EntraIdToken {
    /// The tenant's RS256 modulus and Barrett parameters (2048-bit, 18 limbs).
    pub modulus_limbs: [u128; 18],
    pub redc_params_limbs: [u128; 18],
    /// The canonical lowercase tenant GUID; it fixes the issuer.
    pub tenant: [u8; 36],
    /// The client (application) id that the token must name as `aud`.
    pub audience: BoundedVec<u8, 128>,
    /// The token's `sub` (pairwise per application).
    pub subject: BoundedVec<u8, 256>,
    pub header_b64: BoundedVec<u8, 256>,
    pub payload_b64: BoundedVec<u8, 2048>,
    pub signature_b64: BoundedVec<u8, 344>,
}

impl EntraIdToken {
    /// Poseidon2 of the key material. Both limb arrays are hashed: the
    /// verifier uses the supplied Barrett parameters.
    pub fn key_hash(self) -> Field {
        rsa_key_hash(self.modulus_limbs, self.redc_params_limbs)
    }

    /// The hash of the tenant's issuer string. `tenant_issuer` rejects a
    /// tenant that is not a canonical lowercase GUID.
    pub fn issuer_name(self) -> Field {
        bounded_bytes_hash(tenant_issuer(self.tenant))
    }

    /// The trust root that this input pins: key, tenant issuer and audience.
    pub fn issuer(self) -> Field {
        issuer_pin(
            self.key_hash(),
            self.issuer_name(),
            bounded_bytes_hash(self.audience),
        )
    }
}

impl OidcProviderInput for EntraIdToken {
    let SCHEME: u32 = 13;

    /// The pinned key, tenant, audience and subject.
    fn policy_hash(self) -> Field {
        poseidon2_hash([self.issuer(), bounded_bytes_hash(self.subject)])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        let result = verify_entra_with_iat(
            JwtInput::<256, 2048, 344> {
                header_b64: self.header_b64,
                payload_b64: self.payload_b64,
                signature_b64: self.signature_b64,
            },
            self.tenant,
            self.audience,
            self.subject,
            nonce,
            now,
            TrustedRsaKey { modulus_limbs: self.modulus_limbs, redc_params_limbs: self.redc_params_limbs },
        );
        OidcLogin {
            issuer: self.issuer(),
            subject: subject_id(self.issuer_name(), bounded_bytes_hash(self.subject)),
            expiry: result.claims.expiry,
            issued_at: result.issued_at,
            attribute_kind: KIND_TENANT,
            // `tenant_attribute(self.tenant)`, the verified issuer's hash.
            attribute: self.issuer_name(),
        }
    }
}

/// `OidcLogin.issued_at` is the token's signed `iat`.
impl SignedIssueTime for EntraIdToken {}
