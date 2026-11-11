//! Attribute-gating core (use cases U3 and U1b): "a credential with attribute
//! A was presented; a fixed effect happens". The effect is fixed by the
//! contract, so the outcome does not depend on who submits.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_trust::{assert_trust_accepted, Binding, Trust, TrustPolicy};

mod tests;

pub global DOMAIN_GATE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_GATE_V1".as_bytes()) };
pub global DOMAIN_GATE_BINDING: Field = comptime { poseidon2_hash_bytes("MIKE_UC_GATE_BINDING_V1".as_bytes()) };
pub global DOMAIN_GATE_TERMS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_GATE_TERMS_V1".as_bytes()) };

/// Attribute kinds (`AttributeClaim.kind`). Instances may add kinds above 1000.
pub global KIND_AGE_AT_LEAST_18: u32 = 1; // value 1 when the issuer attests age >= 18
pub global KIND_ASSURANCE_LEVEL: u32 = 2; // issuer-defined assurance level (eIDAS, acr)
pub global KIND_TENANT: u32 = 3; // directory tenant (Entra), employer
pub global KIND_EMAIL_DOMAIN: u32 = 4; // Poseidon2 of the DKIM-signed sender domain
pub global KIND_POD_ENTRY: u32 = 5; // a signed POD entry value
pub global KIND_STORAGE_VALUE: u32 = 6; // a proven chain storage value
pub global KIND_ISSUER_AUTHENTIC: u32 = 7; // value 1 when only issuer authenticity is proven (PhilSys)
pub global KIND_AFFILIATION: u32 = 8; // campus affiliation as asserted by the IdP

/// Predicates (`GateTerms.predicate`) over field values read as integers.
pub global PREDICATE_EQ: u8 = 1;
pub global PREDICATE_GE: u8 = 2;
pub global PREDICATE_LE: u8 = 3;

/// What an adapter proves about one presented attribute.
#[derive(Eq, Serialize, Deserialize)]
pub struct AttributeClaim {
    pub trust: Trust,
    /// `KIND_*`.
    pub kind: u32,
    /// The disclosed value or predicate result.
    pub value: Field,
    /// Issuer-scoped stable person or credential id. Nonzero.
    pub subject: Field,
    pub binding: Binding,
    /// 0 if the credential carries no time (PhilSys).
    pub issued_at: u64,
}

/// Deployment terms, committed in the contract's `immutables_hash`.
#[derive(Eq, Serialize, Deserialize)]
pub struct GateTerms {
    pub accepted: TrustPolicy,
    pub kind: u32,
    pub predicate: u8,
    pub threshold: Field,
    /// Freshness ceiling in seconds; capped at `MAX_BEARER_AGE` for bearer evidence.
    pub max_age: u64,
    pub allow_undated: bool,
    /// Accept evidence with no free signed field (anyone with a copy can act first).
    pub allow_unbound: bool,
    /// App scope of the one-use-per-subject nullifier.
    pub scope: Field,
}

impl GateTerms {
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// Implemented by an adapter's input struct for each scheme that discloses an attribute.
pub trait AttributeEvidence {
    let SCHEME: u32;
    /// Verifies the credential and reports the attribute. The adapter puts
    /// `binding` in the credential's free field, when it has one.
    fn verify(self, context: &mut PrivateContext, binding: Field) -> AttributeClaim;
}

/// True when `value predicate threshold` holds; unknown predicates fail.
pub fn predicate_holds(predicate: u8, value: Field, threshold: Field) -> bool {
    if predicate == PREDICATE_EQ {
        value == threshold
    } else if predicate == PREDICATE_GE {
        !value.lt(threshold)
    } else {
        assert(predicate == PREDICATE_LE, "Unknown predicate");
        !threshold.lt(value)
    }
}

/// One use per subject per app scope (siloed by contract address).
pub fn gate_nullifier(scope: Field, subject: Field) -> Field {
    uc_trust::scoped_nullifier(DOMAIN_GATE, scope, subject)
}

/// Gate rules that need no context: trust accepted, the attribute holds, the
/// binding rule, and a subject for the one-use nullifier.
pub fn assert_attribute_claim(terms: GateTerms, claim: AttributeClaim, binding: Field) {
    assert_trust_accepted(claim.trust, terms.accepted);
    assert(claim.kind == terms.kind, "Wrong attribute kind");
    assert(predicate_holds(terms.predicate, claim.value, terms.threshold), "Attribute predicate false");
    uc_trust::assert_binding(claim.binding, binding, terms.allow_unbound);
    assert(claim.subject != 0, "Missing subject");
}

/// Applies the gate with a fixed effect: binds the terms to the contract,
/// then applies `gate_with_bound_terms`.
pub fn gate<E>(context: &mut PrivateContext, terms: GateTerms, evidence: E) -> AttributeClaim
where
    E: AttributeEvidence,
{
    uc_trust::bind_terms(context, DOMAIN_GATE_TERMS, E::SCHEME as Field, terms.hash());
    gate_with_bound_terms(context, terms, evidence)
}

/// As `gate`, with a free argument (for example a vote choice). Only
/// holder-chosen evidence may carry it.
pub fn gate_with_choice<E>(context: &mut PrivateContext, terms: GateTerms, evidence: E, choice: Field) -> AttributeClaim
where
    E: AttributeEvidence,
{
    uc_trust::bind_terms(context, DOMAIN_GATE_TERMS, E::SCHEME as Field, terms.hash());
    gate_with_choice_with_bound_terms(context, terms, evidence, choice)
}

/// As `gate`, for a caller that has already authenticated `terms`.
pub fn gate_with_bound_terms<E>(context: &mut PrivateContext, terms: GateTerms, evidence: E) -> AttributeClaim
where
    E: AttributeEvidence,
{
    let binding = uc_trust::caller_binding(
        DOMAIN_GATE_BINDING,
        context.chain_id(),
        context.version(),
        context.this_address(),
        uc_trust::msg_sender(*context),
    );
    let claim = evidence.verify(context, binding);
    apply(context, terms, claim, binding);
    claim
}

/// As `gate_with_choice`, for a caller that has already authenticated `terms`.
pub fn gate_with_choice_with_bound_terms<E>(
    context: &mut PrivateContext,
    terms: GateTerms,
    evidence: E,
    choice: Field,
) -> AttributeClaim
where
    E: AttributeEvidence,
{
    let binding = uc_trust::caller_choice_binding(
        DOMAIN_GATE_BINDING,
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

fn apply(context: &mut PrivateContext, terms: GateTerms, claim: AttributeClaim, binding: Field) {
    assert_attribute_claim(terms, claim, binding);
    uc_trust::require_fresh_or_undated(
        context,
        claim.issued_at,
        uc_trust::effective_max_age(terms.max_age, claim.trust),
        terms.allow_undated,
    );
    context.push_nullifier_unsafe(gate_nullifier(terms.scope, claim.subject));
}
