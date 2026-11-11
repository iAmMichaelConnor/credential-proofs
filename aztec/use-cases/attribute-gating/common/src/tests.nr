// Plain unit tests of the context-free gate rules; TXE tests are in
// aztec/use-cases/testing/core_tests.
use crate::{
    assert_attribute_claim, AttributeClaim, gate_nullifier, GateTerms, KIND_AGE_AT_LEAST_18, KIND_ASSURANCE_LEVEL,
    PREDICATE_EQ, PREDICATE_GE, predicate_holds, PREDICATE_LE,
};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, SET_BY_NONE, SET_BY_PROVER, SOURCE_DOCUMENT_ISSUER, Trust, TrustPolicy,
};

fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: 6,
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

fn claim(binding: Field) -> AttributeClaim {
    AttributeClaim {
        trust: Trust {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: 6,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            finality: 0,
            also_authorised: ALSO_COPY_HOLDER,
        },
        kind: KIND_AGE_AT_LEAST_18,
        value: 1,
        subject: 77,
        binding: Binding { value: binding, set_by: SET_BY_PROVER },
        issued_at: 1,
    }
}

#[test]
fn matching_attribute_accepted() {
    assert_attribute_claim(terms(), claim(5), 5);
}

#[test(should_fail_with = "Attribute predicate false")]
fn predicate_false_rejected() {
    let mut c = claim(5);
    c.value = 0;
    assert_attribute_claim(terms(), c, 5);
}

#[test(should_fail_with = "Wrong attribute kind")]
fn wrong_kind_rejected() {
    let mut c = claim(5);
    c.kind = KIND_ASSURANCE_LEVEL;
    assert_attribute_claim(terms(), c, 5);
}

#[test(should_fail_with = "Evidence bound to another value")]
fn wrong_binding_rejected() {
    assert_attribute_claim(terms(), claim(4), 5);
}

#[test(should_fail_with = "Unbound evidence not accepted")]
fn unbound_evidence_needs_explicit_terms() {
    let mut c = claim(0);
    c.binding.set_by = SET_BY_NONE;
    assert_attribute_claim(terms(), c, 5);
}

#[test(should_fail_with = "Untrusted issuer")]
fn wrong_issuer_rejected() {
    let mut c = claim(5);
    c.trust.issuer = 7;
    assert_attribute_claim(terms(), c, 5);
}

#[test(should_fail_with = "Missing subject")]
fn missing_subject_rejected() {
    let mut c = claim(5);
    c.subject = 0;
    assert_attribute_claim(terms(), c, 5);
}

#[test]
fn predicates() {
    assert(predicate_holds(PREDICATE_EQ, 3, 3));
    assert(!predicate_holds(PREDICATE_EQ, 3, 4));
    assert(predicate_holds(PREDICATE_GE, 3, 3));
    assert(predicate_holds(PREDICATE_GE, 4, 3));
    assert(!predicate_holds(PREDICATE_GE, 2, 3));
    assert(predicate_holds(PREDICATE_LE, 3, 3));
    assert(predicate_holds(PREDICATE_LE, 2, 3));
    assert(!predicate_holds(PREDICATE_LE, 4, 3));
    // Field values compare as integers, including near the modulus.
    assert(predicate_holds(PREDICATE_GE, -1, 3));
}

#[test(should_fail_with = "Unknown predicate")]
fn unknown_predicate_rejected() {
    let _ = predicate_holds(9, 1, 1);
}

#[test]
fn nullifier_is_per_subject_and_scope() {
    assert(gate_nullifier(1, 77) != gate_nullifier(2, 77));
    assert(gate_nullifier(1, 77) != gate_nullifier(1, 78));
}
