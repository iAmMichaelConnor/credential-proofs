//! Login-link core (use case U2): "whoever controls this external identity
//! just logged in, and the login was bound to this Aztec caller".
use aztec::{
    context::PrivateContext,
    protocol::{
        address::AztecAddress,
        hash::{poseidon2_hash, poseidon2_hash_bytes},
        traits::{Deserialize, Serialize, ToField},
    },
};
use std::meta::derive;
use uc_trust::{assert_trust_accepted, Binding, SET_BY_NONE, Trust, TrustPolicy};

mod tests;

pub global DOMAIN_LINK: Field = comptime { poseidon2_hash_bytes("MIKE_UC_LOGIN_LINK_V1".as_bytes()) };
pub global DOMAIN_LINK_CHALLENGE: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_LOGIN_LINK_CHALLENGE_V1".as_bytes()) };
pub global DOMAIN_LINK_TERMS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_LOGIN_LINK_TERMS_V1".as_bytes()) };
pub global DOMAIN_LINK_TIMED: Field = comptime { poseidon2_hash_bytes("MIKE_UC_LOGIN_LINK_TIMED_V1".as_bytes()) };

/// What an adapter proves about one login.
#[derive(Eq, Serialize, Deserialize)]
pub struct LinkClaim {
    pub trust: Trust,
    /// Poseidon2(issuer, subject), the key or commitment for user keys, or a
    /// scheme identifier (mailbox, handle) that the deployment's pinned
    /// issuer scopes. Nonzero.
    pub identity: Field,
    /// Must equal the link challenge, unless `bearer`.
    pub binding: Binding,
    /// When the login happened (signed `iat` or equivalent).
    pub issued_at: u64,
    /// Exclusive signed expiry; 0 if the credential carries none.
    pub expires_at: u64,
    /// True exactly when the credential carries no challenge (LinkedIn).
    pub bearer: bool,
}

/// Deployment terms, committed in the contract's `immutables_hash`.
#[derive(Eq, Serialize, Deserialize)]
pub struct LinkTerms {
    pub accepted: TrustPolicy,
    /// Freshness ceiling for the login, in seconds.
    pub max_age: u64,
    /// Bearer logins are refused unless the terms accept them explicitly.
    pub allow_bearer: bool,
    /// App scope of the one-link-per-identity nullifier.
    pub scope: Field,
    /// Challenge round; a new round needs a new deployment.
    pub round: Field,
}

impl LinkTerms {
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// Implemented by an adapter's input struct for each scheme that supports login-link.
pub trait LoginLink {
    let SCHEME: u32;
    /// Verifies the login and reports what it proved. The adapter puts
    /// `challenge` in the credential's free field (nonce, body, context).
    fn verify(self, context: &mut PrivateContext, challenge: Field) -> LinkClaim;
}

/// The value a login must bind for this caller, contract, chain and round.
pub fn link_challenge(
    chain_id: Field,
    version: Field,
    this_address: AztecAddress,
    sender: AztecAddress,
    round: Field,
) -> Field {
    poseidon2_hash(
        [DOMAIN_LINK_CHALLENGE, chain_id, version, this_address.to_field(), sender.to_field(), round],
    )
}

/// The value that a user key signs when its credential carries no time of
/// its own (a passkey assertion, a Zupass holder signature or a JPKI
/// card signature): the link challenge and the issue time that the
/// signer states. The adapter reports that time as `issued_at`. Only the
/// signer vouches for it: it limits how long the signature stays usable
/// after the signer made it (for example while a relayer holds it), but the
/// signer can state any past time.
pub fn timed_challenge(challenge: Field, issued_at: u64) -> Field {
    poseidon2_hash([DOMAIN_LINK_TIMED, challenge, issued_at as Field])
}

/// One link per identity per app scope (siloed by contract address).
pub fn link_nullifier(scope: Field, identity: Field) -> Field {
    uc_trust::scoped_nullifier(DOMAIN_LINK, scope, identity)
}

/// Login-link rules that need no context: trust accepted, the challenge is
/// bound unless the login is a bearer login that the terms accept, and the
/// identity is set.
pub fn assert_link_claim(terms: LinkTerms, claim: LinkClaim, challenge: Field) {
    assert_trust_accepted(claim.trust, terms.accepted);
    assert(claim.bearer == (claim.binding.set_by == SET_BY_NONE), "Inconsistent bearer flag");
    if claim.bearer {
        assert(terms.allow_bearer, "Bearer login not accepted");
    } else {
        assert(claim.binding.value == challenge, "Login bound to another challenge");
    }
    assert(claim.identity != 0, "Missing identity");
}

/// Links the caller to the external identity: binds the terms to the
/// contract, then applies `link_with_bound_terms`. The instance records the
/// link for the caller (its fixed effect).
pub fn link<E>(context: &mut PrivateContext, terms: LinkTerms, evidence: E) -> LinkClaim
where
    E: LoginLink,
{
    uc_trust::bind_terms(context, DOMAIN_LINK_TERMS, E::SCHEME as Field, terms.hash());
    link_with_bound_terms(context, terms, evidence)
}

/// As `link`, for a caller that has already authenticated `terms`.
pub fn link_with_bound_terms<E>(context: &mut PrivateContext, terms: LinkTerms, evidence: E) -> LinkClaim
where
    E: LoginLink,
{
    let sender = uc_trust::msg_sender(*context);
    let challenge = link_challenge(
        context.chain_id(),
        context.version(),
        context.this_address(),
        sender,
        terms.round,
    );
    let claim = evidence.verify(context, challenge);
    assert_link_claim(terms, claim, challenge);
    uc_trust::require_fresh(
        context,
        claim.issued_at,
        uc_trust::effective_max_age(terms.max_age, claim.trust),
    );
    uc_trust::require_unexpired(context, claim.expires_at);
    context.push_nullifier_unsafe(link_nullifier(terms.scope, claim.identity));
    claim
}
