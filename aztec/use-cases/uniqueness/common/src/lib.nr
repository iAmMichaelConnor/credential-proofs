//! Uniqueness core (use cases U4 and U1b): "this person has not done this in
//! this app before; a fixed effect happens". The upstream AnonAadhaarVote
//! pattern: the proof binds the caller, the evidence is fresh, one action per
//! person, and the effect is fixed.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_trust::{assert_trust_accepted, Binding, Trust, TrustPolicy};

mod tests;

pub global DOMAIN_UNIQUE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_UNIQUENESS_V1".as_bytes()) };
pub global DOMAIN_UNIQUE_BINDING: Field = comptime { poseidon2_hash_bytes("MIKE_UC_UNIQUENESS_BINDING_V1".as_bytes()) };
pub global DOMAIN_UNIQUE_TERMS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_UNIQUENESS_TERMS_V1".as_bytes()) };

/// What "person" means (`UniquenessClaim.person_kind`).
pub global PERSON_WORLD_ID_IDENTITY: u8 = 1; // a World ID identity nullifier
pub global PERSON_WORLD_ID_ACCOUNT: u8 = 2; // a World ID account nullifier
pub global PERSON_NATIONAL_ID: u8 = 3; // a national-ID-derived nullifier (Aadhaar)
pub global PERSON_PAIRWISE_SUBJECT: u8 = 4; // an eID subject that is stable per client (govbr, FranceConnect, Singpass)

/// What an adapter proves about one person.
#[derive(Eq, Serialize, Deserialize)]
pub struct UniquenessClaim {
    pub trust: Trust,
    /// Issuer-scoped person id. Nonzero.
    pub person: Field,
    /// `PERSON_*`.
    pub person_kind: u8,
    pub binding: Binding,
    /// 0 if the evidence carries no time.
    pub issued_at: u64,
}

/// Deployment terms, committed in the contract's `immutables_hash`.
#[derive(Eq, Serialize, Deserialize)]
pub struct UniqueTerms {
    pub accepted: TrustPolicy,
    pub person_kind: u8,
    /// Freshness ceiling in seconds; capped at `MAX_BEARER_AGE` for bearer evidence.
    pub max_age: u64,
    pub allow_undated: bool,
    pub allow_unbound: bool,
    /// App scope of the person nullifier. It separates actions that share
    /// one contract (for example several `*_with_bound_terms` uses). It adds
    /// nothing across deployments: Aztec silos nullifiers by contract
    /// address, and the address commits to these terms, including
    /// `accepted.issuer` and a pinned `accepted.anchor`. A key rotation or a
    /// new pinned root therefore needs a new deployment, whose nullifier set
    /// is empty, so every person can act once more there. Only
    /// `ANCHOR_REGISTRY` root updates keep the same deployment.
    pub scope: Field,
}

impl UniqueTerms {
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// Implemented by an adapter's input struct for each scheme with a person id.
pub trait UniquenessEvidence {
    let SCHEME: u32;
    /// Verifies the evidence and reports the person. The adapter puts
    /// `binding` in the evidence's free field (signal, nonce).
    fn verify(self, context: &mut PrivateContext, binding: Field) -> UniquenessClaim;
}

/// One action per person per app scope within one contract (Aztec silos it
/// by contract address).
pub fn person_nullifier(scope: Field, person: Field) -> Field {
    uc_trust::scoped_nullifier(DOMAIN_UNIQUE, scope, person)
}

/// Uniqueness rules that need no context.
pub fn assert_uniqueness_claim(terms: UniqueTerms, claim: UniquenessClaim, binding: Field) {
    assert_trust_accepted(claim.trust, terms.accepted);
    assert(claim.person_kind == terms.person_kind, "Wrong person kind");
    assert(claim.person != 0, "Missing person");
    uc_trust::assert_binding(claim.binding, binding, terms.allow_unbound);
}

/// One action per person with a fixed effect: binds the terms to the
/// contract, then applies `once_with_bound_terms`.
pub fn once<E>(context: &mut PrivateContext, terms: UniqueTerms, evidence: E) -> UniquenessClaim
where
    E: UniquenessEvidence,
{
    uc_trust::bind_terms(
        context,
        DOMAIN_UNIQUE_TERMS,
        E::SCHEME as Field,
        terms.hash(),
    );
    once_with_bound_terms(context, terms, evidence)
}

/// As `once`, with a free argument (for example a vote choice). Only
/// holder-chosen evidence may carry it (World ID: yes; Aadhaar QR: no).
pub fn once_with_choice<E>(
    context: &mut PrivateContext,
    terms: UniqueTerms,
    evidence: E,
    choice: Field,
) -> UniquenessClaim
where
    E: UniquenessEvidence,
{
    uc_trust::bind_terms(
        context,
        DOMAIN_UNIQUE_TERMS,
        E::SCHEME as Field,
        terms.hash(),
    );
    once_with_choice_with_bound_terms(context, terms, evidence, choice)
}

/// As `once`, for a caller that has already authenticated `terms`.
pub fn once_with_bound_terms<E>(context: &mut PrivateContext, terms: UniqueTerms, evidence: E) -> UniquenessClaim
where
    E: UniquenessEvidence,
{
    let binding = uc_trust::caller_binding(
        DOMAIN_UNIQUE_BINDING,
        context.chain_id(),
        context.version(),
        context.this_address(),
        uc_trust::msg_sender(*context),
    );
    let claim = evidence.verify(context, binding);
    apply(context, terms, claim, binding);
    claim
}

/// As `once_with_choice`, for a caller that has already authenticated `terms`.
pub fn once_with_choice_with_bound_terms<E>(
    context: &mut PrivateContext,
    terms: UniqueTerms,
    evidence: E,
    choice: Field,
) -> UniquenessClaim
where
    E: UniquenessEvidence,
{
    let binding = uc_trust::caller_choice_binding(
        DOMAIN_UNIQUE_BINDING,
        context.chain_id(),
        context.version(),
        context.this_address(),
        uc_trust::msg_sender(*context),
        choice,
    );
    let claim = evidence.verify(context, binding);
    uc_trust::assert_choice_allowed(claim.binding);
    apply(context, terms, claim, binding);
    claim
}

fn apply(context: &mut PrivateContext, terms: UniqueTerms, claim: UniquenessClaim, binding: Field) {
    assert_uniqueness_claim(terms, claim, binding);
    uc_trust::require_fresh_or_undated(
        context,
        claim.issued_at,
        uc_trust::effective_max_age(terms.max_age, claim.trust),
        terms.allow_undated,
    );
    context.push_nullifier_unsafe(person_nullifier(terms.scope, claim.person));
}
