//! OIDC family adapter: one generic shape for every
//! OIDC provider. A provider adapter implements `OidcProviderInput` on its
//! input struct (token, pinned key and client id) in about 20 lines. The
//! wrappers here turn a verified login into the claim of each use case that
//! OIDC supports: account authorisation, login link, attribute gating and
//! uniqueness.
//!
//! What an OIDC login proves (category 3): the identity provider asserts that
//! the subject just logged in at the client, and the token carries the nonce
//! that the client chose. The wrappers put the use-case value (action hash,
//! link challenge, caller binding) in that nonce, as lowercase hex. The
//! identity provider and the client operator can also produce such a token
//! for any value, so every claim carries `ALSO_IDP | ALSO_CLIENT_OPERATOR`
//! and `SET_BY_CLIENT`.
//!
//! Accounts: an account's entrypoint ABI names the contract crate's own input
//! struct. The account keeps `AuthInput` in the contract crate, implements
//! `OidcProviderInput` for it there, and passes `OidcAccount { input: auth }`
//! to `uc_account::entrypoint` inside the entrypoint body, so the wrapper is
//! not part of the ABI.
use aztec::{context::PrivateContext, protocol::hash::{poseidon2_hash, poseidon2_hash_bytes}};
use uc_account::{AccountAuthorisation, AccountGrant};
use uc_attribute_gate::{AttributeClaim, AttributeEvidence};
use uc_login_link::{LinkClaim, LoginLink};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_COPY_HOLDER, ALSO_IDP, ANCHOR_NONE, Binding, SET_BY_CLIENT, SET_BY_NONE,
    SOURCE_IDENTITY_PROVIDER, Trust,
};
use uc_uniqueness::{PERSON_PAIRWISE_SUBJECT, UniquenessClaim, UniquenessEvidence};

mod tests;

pub global DOMAIN_OIDC_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_OIDC_ISSUER_V1".as_bytes()) };
pub global DOMAIN_OIDC_SUBJECT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_OIDC_SUBJECT_V1".as_bytes()) };

/// What a provider adapter proves about one verified ID token.
pub struct OidcLogin {
    /// The trust root that the input pins: `issuer_pin(key, issuer name,
    /// audience)`. It becomes `Trust.issuer`, so the terms pin the provider
    /// key and the client id together. A token for another client, or under
    /// another key, gives another value.
    pub issuer: Field,
    /// The issuer-scoped subject: `subject_id(issuer name, sub)`. It does not
    /// depend on the key, so it stays the same across a key rotation. Nonzero.
    pub subject: Field,
    /// The exclusive expiry: the signed `exp`, or an earlier bound that the
    /// provider adapter documents. The provider check requires it to be after
    /// `now`, so it is at least 1.
    pub expiry: u64,
    /// The signed issue time (`iat`), or the value that the provider adapter
    /// documents when the provider library does not return `iat`.
    pub issued_at: u64,
    /// The attribute-gating kind (`uc_attribute_gate::KIND_*`) of
    /// `attribute`; 0 when the provider profile discloses no attribute.
    pub attribute_kind: u32,
    /// The disclosed attribute value (assurance level, tenant, affiliation).
    pub attribute: Field,
}

/// Implemented by each OIDC provider adapter on its input struct.
pub trait OidcProviderInput {
    /// The scheme id of the provider.
    let SCHEME: u32;
    /// Poseidon2 of the serialised account policy (accounts only; other use
    /// cases pin the provider through `OidcLogin.issuer` and their terms).
    fn policy_hash(self) -> Field;
    /// Verifies the token signature under the pinned key and checks the
    /// issuer, audience, `nonce` (exactly; an empty `nonce` only for a
    /// provider without a nonce claim), `exp > now` and `nbf <= now`.
    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin;
}

/// Implemented, in addition to `OidcProviderInput`, by a provider adapter
/// whose `OidcLogin.issued_at` is the token's signed `iat`, read from the
/// signed payload by the provider library. An adapter that derives the issue
/// time (for example `exp` minus a lifetime) must not implement it.
/// `OidcBearerLink` requires it: a bearer token has no challenge, so its
/// signed age is the only limit on how long a copy stays usable
/// (`MAX_BEARER_AGE`), and a derived age could hide an old token
///.
pub trait SignedIssueTime {}

/// The nonce that binds `value`: its canonical lowercase hex, without 0x,
/// as `uc_account::action_hex` gives for accounts.
pub fn nonce_of(value: Field) -> BoundedVec<u8, 64> {
    BoundedVec::from_array(uc_trust::field_hex(value))
}

/// Poseidon2 of the first `len` bytes and the length. Bytes after `len` in
/// the storage of a prover-supplied `BoundedVec` are ignored, so one string
/// has one hash.
pub fn bounded_bytes_hash<let N: u32>(bytes: BoundedVec<u8, N>) -> Field {
    let mut canonical = [0; N];
    for i in 0..N {
        if i < bytes.len() {
            canonical[i] = bytes.get_unchecked(i);
        }
    }
    poseidon2_hash([bytes.len() as Field, poseidon2_hash_bytes(canonical)])
}

/// The trust root of a provider input: the hash of the trusted key
/// material, the issuer name and the audience (client id).
pub fn issuer_pin(key_hash: Field, issuer_name: Field, audience_hash: Field) -> Field {
    poseidon2_hash([DOMAIN_OIDC_ISSUER, key_hash, issuer_name, audience_hash])
}

/// Poseidon2 of a 2048-bit RSA key as the OIDC components take it (modulus
/// and Barrett parameters, 18 limbs each). Both arrays are hashed: the
/// verifier uses the supplied Barrett parameters.
pub fn rsa_key_hash(modulus_limbs: [u128; 18], redc_params_limbs: [u128; 18]) -> Field {
    let mut limbs = [0; 36];
    for i in 0..18 {
        limbs[i] = modulus_limbs[i] as Field;
        limbs[18 + i] = redc_params_limbs[i] as Field;
    }
    poseidon2_hash(limbs)
}

/// Poseidon2 of a 4096-bit RSA key as the OIDC components take it (modulus
/// and Barrett parameters, 35 limbs each), as `rsa_key_hash` for 2048 bits.
pub fn rsa4096_key_hash(modulus_limbs: [u128; 35], redc_params_limbs: [u128; 35]) -> Field {
    let mut limbs = [0; 70];
    for i in 0..35 {
        limbs[i] = modulus_limbs[i] as Field;
        limbs[35 + i] = redc_params_limbs[i] as Field;
    }
    poseidon2_hash(limbs)
}

/// Poseidon2 of a P-256 key's affine coordinates (big-endian bytes).
pub fn p256_key_hash(x: [u8; 32], y: [u8; 32]) -> Field {
    let mut bytes = [0; 64];
    for i in 0..32 {
        bytes[i] = x[i];
        bytes[32 + i] = y[i];
    }
    poseidon2_hash_bytes(bytes)
}

/// The identity of a subject at an issuer.
pub fn subject_id(issuer_name: Field, subject_hash: Field) -> Field {
    poseidon2_hash([DOMAIN_OIDC_SUBJECT, issuer_name, subject_hash])
}

/// Trust of an OIDC login: the identity provider produced it, and the
/// provider and the client operator can produce one for any nonce.
pub fn oidc_trust(issuer: Field, also_authorised: u8) -> Trust {
    Trust {
        source: SOURCE_IDENTITY_PROVIDER,
        issuer,
        anchor_kind: ANCHOR_NONE,
        anchor: 0,
        finality: 0,
        also_authorised,
    }
}

fn anchor_timestamp(context: &mut PrivateContext) -> u64 {
    context.get_anchor_block_header().timestamp()
}

/// Account authorisation (U1). The nonce is the action hash.
pub struct OidcAccount<P> {
    pub input: P,
}

impl<P> AccountAuthorisation for OidcAccount<P>
where
    P: OidcProviderInput,
{
    let SCHEME: u32 = P::SCHEME;

    fn policy_hash(self) -> Field {
        self.input.policy_hash()
    }

    fn authorise(self, context: &mut PrivateContext, action: Field) -> AccountGrant {
        let login = self.input.verify(nonce_of(action), anchor_timestamp(context));
        // The account path uses the uc_account constructors (bytecode stability).
        // also_authorised 3 = ALSO_IDP | ALSO_CLIENT_OPERATOR.
        AccountGrant {
            trust: uc_account::identity_provider_trust(login.issuer, 3),
            binding: uc_account::client_bound(action),
            // Inclusion strictly before the exclusive signed expiry.
            expiration_timestamp: Option::some(login.expiry - 1),
            session_nullifier: Option::none(),
        }
    }
}

/// Login link (U2). The nonce is the link challenge.
pub struct OidcLink<P> {
    pub input: P,
}

impl<P> LoginLink for OidcLink<P>
where
    P: OidcProviderInput,
{
    let SCHEME: u32 = P::SCHEME;

    fn verify(self, context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        let login = self.input.verify(nonce_of(challenge), anchor_timestamp(context));
        LinkClaim {
            trust: oidc_trust(login.issuer, ALSO_IDP | ALSO_CLIENT_OPERATOR),
            identity: login.subject,
            binding: Binding { value: challenge, set_by: SET_BY_CLIENT },
            issued_at: login.issued_at,
            expires_at: login.expiry,
            bearer: false,
        }
    }
}

/// Login link for a provider whose token has no nonce claim (LinkedIn). The
/// provider gets an empty nonce, and the claim is labelled bearer: anyone
/// who holds the token can link it, including the client operator that
/// receives it. `uc_login_link` accepts it
/// only when the terms set `allow_bearer`, and caps its age at
/// `MAX_BEARER_AGE`. The provider must report its signed `iat`
/// (`SignedIssueTime`).
pub struct OidcBearerLink<P> {
    pub input: P,
}

impl<P> LoginLink for OidcBearerLink<P>
where
    P: OidcProviderInput + SignedIssueTime,
{
    let SCHEME: u32 = P::SCHEME;

    fn verify(self, context: &mut PrivateContext, _challenge: Field) -> LinkClaim {
        let login = self.input.verify(BoundedVec::new(), anchor_timestamp(context));
        LinkClaim {
            trust: oidc_trust(
                login.issuer,
                ALSO_IDP | ALSO_CLIENT_OPERATOR | ALSO_COPY_HOLDER,
            ),
            identity: login.subject,
            binding: Binding { value: 0, set_by: SET_BY_NONE },
            issued_at: login.issued_at,
            expires_at: login.expiry,
            bearer: true,
        }
    }
}

/// Attribute gating (U3 + U1b). The nonce is the caller binding (or the
/// caller-and-choice binding), so the token is good only for this caller.
pub struct OidcAttribute<P> {
    pub input: P,
}

impl<P> AttributeEvidence for OidcAttribute<P>
where
    P: OidcProviderInput,
{
    let SCHEME: u32 = P::SCHEME;

    fn verify(self, context: &mut PrivateContext, binding: Field) -> AttributeClaim {
        let login = self.input.verify(nonce_of(binding), anchor_timestamp(context));
        assert(login.attribute_kind != 0, "Provider discloses no attribute");
        // The gate core has no credential expiry; limit inclusion here.
        uc_trust::require_unexpired(context, login.expiry);
        AttributeClaim {
            trust: oidc_trust(login.issuer, ALSO_IDP | ALSO_CLIENT_OPERATOR),
            kind: login.attribute_kind,
            value: login.attribute,
            subject: login.subject,
            binding: Binding { value: binding, set_by: SET_BY_CLIENT },
            issued_at: login.issued_at,
        }
    }
}

/// Uniqueness (U4 + U1b), for providers whose subject is one per person at
/// the client. The person is the
/// issuer-scoped subject, labelled `PERSON_PAIRWISE_SUBJECT`.
pub struct OidcUniqueness<P> {
    pub input: P,
}

impl<P> UniquenessEvidence for OidcUniqueness<P>
where
    P: OidcProviderInput,
{
    let SCHEME: u32 = P::SCHEME;

    fn verify(self, context: &mut PrivateContext, binding: Field) -> UniquenessClaim {
        let login = self.input.verify(nonce_of(binding), anchor_timestamp(context));
        // The uniqueness core has no credential expiry; limit inclusion here.
        uc_trust::require_unexpired(context, login.expiry);
        UniquenessClaim {
            trust: oidc_trust(login.issuer, ALSO_IDP | ALSO_CLIENT_OPERATOR),
            person: login.subject,
            person_kind: PERSON_PAIRWISE_SUBJECT,
            binding: Binding { value: binding, set_by: SET_BY_CLIENT },
            issued_at: login.issued_at,
        }
    }
}
