use crate::{deploy_with_immutables, in_context, requested_expiry};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::TestEnvironment,
};
use uc_attribute_gate::{
    AttributeClaim, AttributeEvidence, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms,
    gate_with_choice, gate_with_choice_with_bound_terms, GateTerms, KIND_AGE_AT_LEAST_18, PREDICATE_EQ,
};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, caller_binding, caller_choice_binding, SET_BY_HOLDER, SET_BY_NONE,
    SET_BY_PROVER, SOURCE_DOCUMENT_ISSUER, terms_commitment, Trust, TrustPolicy,
};

global SCHEME: u32 = 9003;

global ISSUER_KEY: Field = 0x0a0a;

/// A dummy static document (Aadhaar-like): the issuer signs the holder's
/// attributes once; the presentation proof binds a free `signal` that any
/// prover chooses. `issued_at == 0` models an undated document.
pub struct DummyDocument<let N: u32> {
    pub issuer_key: Field,
    pub document_id: Field,
    pub attributes: [Field; N],
    pub issued_at: u64,
    pub signal: Field,
    pub set_by: u8,
    pub tag: Field,
}

impl<let N: u32> DummyDocument<N> {
    fn new(attributes: [Field; N], issued_at: u64, signal: Field, set_by: u8) -> Self {
        let mut document =
            DummyDocument { issuer_key: ISSUER_KEY, document_id: 31, attributes, issued_at, signal, set_by, tag: 0 };
        document.tag = document.signed();
        document
    }

    fn signed(self) -> Field {
        poseidon2_hash(
            [self.issuer_key, self.document_id, poseidon2_hash(self.attributes), self.issued_at as Field],
        )
    }
}

impl<let N: u32> AttributeEvidence for DummyDocument<N> {
    let SCHEME: u32 = 9003;

    fn verify(self, _context: &mut PrivateContext, _binding: Field) -> AttributeClaim {
        assert(self.tag == self.signed(), "Bad document signature");
        AttributeClaim {
            trust: Trust {
                source: SOURCE_DOCUMENT_ISSUER,
                issuer: poseidon2_hash([self.issuer_key]),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: if self.set_by == SET_BY_HOLDER {
                    0
                } else {
                    ALSO_COPY_HOLDER
                },
            },
            kind: KIND_AGE_AT_LEAST_18,
            value: self.attributes[0],
            subject: poseidon2_hash([self.issuer_key, self.document_id]),
            binding: Binding {
                value: if self.set_by == SET_BY_NONE {
                    0
                } else {
                    self.signal
                },
                set_by: self.set_by,
            },
            issued_at: self.issued_at,
        }
    }
}

fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: poseidon2_hash([ISSUER_KEY]),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_AGE_AT_LEAST_18,
        predicate: PREDICATE_EQ,
        threshold: 1,
        max_age: 10800,
        allow_undated: false,
        allow_unbound: false,
        scope: 1,
    }
}

/// Presents a document whose signal is this caller's binding, or `signal`
/// when nonzero, and returns the requested inclusion expiry. With `at`, the
/// public `gate` runs at that deployed contract; without it,
/// `gate_with_bound_terms` runs at the TXE default address.
unconstrained fn present_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: GateTerms,
    adult: Field,
    age: u64,
    signal: Field,
    set_by: u8,
) -> u64 {
    let now = env.last_block_timestamp();
    in_context(
        env,
        at,
        |context| {
            let binding = caller_binding(
                DOMAIN_GATE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
            );
            let issued_at = if age == 0 { 0 } else { now - age };
            let document = DummyDocument::new(
                [adult, 7, 9],
                issued_at,
                if signal == 0 { binding } else { signal },
                set_by,
            );
            let _ = if at.is_some() {
                gate(context, terms, document)
            } else {
                gate_with_bound_terms(context, terms, document)
            };
            requested_expiry(context)
        },
    )
}

unconstrained fn present(
    env: TestEnvironment,
    terms: GateTerms,
    adult: Field,
    age: u64,
    signal: Field,
    set_by: u8,
) -> u64 {
    present_at(env, Option::none(), terms, adult, age, signal, set_by)
}

unconstrained fn present_choice_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: GateTerms,
    choice: Field,
    set_by: u8,
) {
    let now = env.last_block_timestamp();
    in_context(
        env,
        at,
        |context| {
            let binding = caller_choice_binding(
                DOMAIN_GATE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                choice,
            );
            let document = DummyDocument::new([1, 7], now - 60, binding, set_by);
            let _ = if at.is_some() {
                gate_with_choice(context, terms, document, choice)
            } else {
                gate_with_choice_with_bound_terms(context, terms, document, choice)
            };
        },
    );
}

unconstrained fn present_choice(env: TestEnvironment, choice: Field, set_by: u8) {
    present_choice_at(env, Option::none(), terms(), choice, set_by);
}

unconstrained fn deploy_gate(env: &mut TestEnvironment, terms: GateTerms) -> AztecAddress {
    deploy_with_immutables(
        env,
        terms_commitment(DOMAIN_GATE_TERMS, SCHEME as Field, terms.hash()),
    )
}

#[test]
unconstrained fn gate_valid_accepted() {
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 1, 60, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "already present")]
unconstrained fn gate_second_use_rejected() {
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 1, 60, 0, SET_BY_PROVER);
    let _ = present(env, terms(), 1, 30, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn gate_predicate_false_rejected() {
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 0, 60, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "Evidence bound to another value")]
unconstrained fn gate_wrong_binding_rejected() {
    // A proof made for another caller (proof theft) is refused.
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 1, 60, 0xbad, SET_BY_PROVER);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn gate_stale_rejected() {
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 1, 10801, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn gate_bearer_ceiling_applies() {
    // The terms allow a day, but copies of bearer evidence get MAX_BEARER_AGE.
    let env = TestEnvironment::new();
    let mut long = terms();
    long.max_age = 86400;
    let _ = present(env, long, 1, 14401, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "Undated evidence not accepted")]
unconstrained fn gate_undated_refused_by_default() {
    let env = TestEnvironment::new();
    let _ = present(env, terms(), 1, 0, 0, SET_BY_PROVER);
}

#[test]
unconstrained fn gate_undated_unbound_accepted_when_allowed() {
    // A PhilSys-like document: no time and no free field.
    let env = TestEnvironment::new();
    let mut open = terms();
    open.allow_undated = true;
    open.allow_unbound = true;
    let _ = present(env, open, 1, 0, 0, SET_BY_NONE);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn gate_wrong_issuer_rejected() {
    let env = TestEnvironment::new();
    let mut other = terms();
    other.accepted.issuer = 1;
    let _ = present(env, other, 1, 60, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "A free choice needs holder-chosen evidence")]
unconstrained fn gate_choice_from_prover_set_evidence_rejected() {
    let env = TestEnvironment::new();
    present_choice(env, 2, SET_BY_PROVER);
}

#[test]
unconstrained fn gate_choice_from_holder_bound_evidence_accepted() {
    let env = TestEnvironment::new();
    present_choice(env, 2, SET_BY_HOLDER);
}

// Inclusion expiry: the core limits inclusion to the freshness deadline.

#[test]
unconstrained fn gate_expiry_is_the_freshness_deadline() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = present(env, terms(), 1, 60, 0, SET_BY_PROVER);
    assert_eq(expiry, now - 60 + 10800);
}

#[test]
unconstrained fn gate_at_the_exact_deadline_accepted() {
    // Issued exactly max_age before the anchor block: accepted, and the
    // transaction must be included at the anchor block timestamp at the latest.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = present(env, terms(), 1, 10800, 0, SET_BY_PROVER);
    assert_eq(expiry, now);
}

#[test]
unconstrained fn gate_bearer_expiry_is_the_bearer_ceiling() {
    // The terms allow a day; copies of bearer evidence get MAX_BEARER_AGE.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut long = terms();
    long.max_age = 86400;
    let expiry = present(env, long, 1, 60, 0, SET_BY_PROVER);
    assert_eq(expiry, now - 60 + 14400);
}

#[test]
unconstrained fn gate_undated_evidence_has_no_freshness_deadline() {
    // Undated evidence accepted under `allow_undated` has no
    // ceiling; only the protocol's maximum transaction lifetime applies.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut open = terms();
    open.allow_undated = true;
    open.allow_unbound = true;
    let expiry = present(env, open, 1, 0, 0, SET_BY_NONE);
    assert(expiry > now + 14400);
}

// The public `gate` and `gate_with_choice` at deployed contracts.

#[test]
unconstrained fn gate_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_gate(&mut env, terms());
    let _ = present_at(env, Option::some(at), terms(), 1, 60, 0, SET_BY_PROVER);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn gate_wrong_terms_rejected() {
    // Terms with a longer freshness window than the contract commits to.
    let mut env = TestEnvironment::new();
    let at = deploy_gate(&mut env, terms());
    let mut longer = terms();
    longer.max_age = 86400;
    let _ = present_at(env, Option::some(at), longer, 1, 60, 0, SET_BY_PROVER);
}

#[test]
unconstrained fn gate_with_choice_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_gate(&mut env, terms());
    present_choice_at(env, Option::some(at), terms(), 2, SET_BY_HOLDER);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn gate_with_choice_wrong_terms_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_gate(&mut env, terms());
    let mut other = terms();
    other.scope = 2;
    present_choice_at(env, Option::some(at), other, 2, SET_BY_HOLDER);
}
