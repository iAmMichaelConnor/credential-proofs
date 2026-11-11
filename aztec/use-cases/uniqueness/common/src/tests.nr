// Plain unit tests of the context-free uniqueness rules; TXE tests are in
// aztec/use-cases/testing/core_tests.
use crate::{
    assert_uniqueness_claim, PERSON_NATIONAL_ID, person_nullifier, PERSON_WORLD_ID_IDENTITY, UniquenessClaim,
    UniqueTerms,
};
use uc_trust::{ANCHOR_REGISTRY, Binding, SET_BY_HOLDER, SOURCE_PROOF_SYSTEM, Trust, TrustPolicy};

fn terms() -> UniqueTerms {
    UniqueTerms {
        accepted: TrustPolicy {
            source: SOURCE_PROOF_SYSTEM,
            issuer: 8,
            anchor_kind: ANCHOR_REGISTRY,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        person_kind: PERSON_WORLD_ID_IDENTITY,
        max_age: 3600,
        allow_undated: false,
        allow_unbound: false,
        scope: 1,
    }
}

fn claim(binding: Field) -> UniquenessClaim {
    UniquenessClaim {
        trust: Trust {
            source: SOURCE_PROOF_SYSTEM,
            issuer: 8,
            anchor_kind: ANCHOR_REGISTRY,
            anchor: 1234,
            finality: 0,
            also_authorised: 0,
        },
        person: 99,
        person_kind: PERSON_WORLD_ID_IDENTITY,
        binding: Binding { value: binding, set_by: SET_BY_HOLDER },
        issued_at: 1,
    }
}

#[test]
fn matching_person_accepted() {
    assert_uniqueness_claim(terms(), claim(5), 5);
}

#[test(should_fail_with = "Wrong person kind")]
fn wrong_person_kind_rejected() {
    let mut c = claim(5);
    c.person_kind = PERSON_NATIONAL_ID;
    assert_uniqueness_claim(terms(), c, 5);
}

#[test(should_fail_with = "Missing person")]
fn missing_person_rejected() {
    let mut c = claim(5);
    c.person = 0;
    assert_uniqueness_claim(terms(), c, 5);
}

#[test(should_fail_with = "Evidence bound to another value")]
fn wrong_binding_rejected() {
    assert_uniqueness_claim(terms(), claim(6), 5);
}

#[test(should_fail_with = "Untrusted evidence source")]
fn wrong_source_rejected() {
    let mut c = claim(5);
    c.trust.source = 6;
    assert_uniqueness_claim(terms(), c, 5);
}

#[test]
fn nullifier_is_per_person_and_scope() {
    assert(person_nullifier(1, 99) != person_nullifier(2, 99));
    assert(person_nullifier(1, 99) != person_nullifier(1, 98));
}
