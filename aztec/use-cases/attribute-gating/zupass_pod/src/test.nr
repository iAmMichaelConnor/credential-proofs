//! TXE tests of the Zupass POD gate. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `gate` (the call that
//! the generated entrypoint makes) at its address with the PODs from
//! `fixture.nr`. The issuer's EdDSA-Poseidon signature and the LeanIMT entry
//! proof are verified by the `zupass` library. Wrong-term cases use separately
//! signed PODs; tampering cases mutate a valid entry. No verification key,
//! proof or network is involved.
use crate::fixture::{
    EVENT, event_entry, negative_entry, other_issuer_event, second_pod_event, second_pod_tier, TIER, tier_entry,
};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, constants::MAX_TX_LIFETIME},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zupass::{SCHEME_ZUPASS_POD, ZupassPodEntry};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms, KIND_POD_ENTRY, PREDICATE_EQ,
    PREDICATE_GE,
};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_NONE, SOURCE_DOCUMENT_ISSUER, terms_commitment, TrustPolicy};

/// The instance's terms: a POD from the fixture issuer whose `event` entry
/// is 42, undated and unbound (a POD has neither a time nor a free field).
fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: event_entry().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_POD_ENTRY,
        predicate: PREDICATE_EQ,
        threshold: EVENT,
        max_age: 0,
        allow_undated: true,
        allow_unbound: true,
        scope: 0x9a7e,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_ZUPASS_POD as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

unconstrained fn setup() -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, terms());
    env.mine_block();
    (env, at)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_attribute_gate::gate`.
unconstrained fn gate_at(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    evidence: ZupassPodEntry,
) -> AttributeClaim {
    at_shell(env, at, |context| gate(context, t, evidence))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    evidence: ZupassPodEntry,
) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate_with_bound_terms(context, t, evidence),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup();
    let claim = gate_at(env, at, terms(), event_entry());
    assert_eq(claim.kind, KIND_POD_ENTRY);
    assert_eq(claim.value, EVENT);
    assert_eq(claim.issued_at, 0);
    assert_eq(claim.binding.set_by, SET_BY_NONE);
    assert_eq(claim.trust.also_authorised, ALSO_COPY_HOLDER);
}

#[test]
unconstrained fn no_inclusion_limit_for_undated_evidence() {
    // An undated POD sets no freshness deadline: only the protocol's maximum
    // transaction lifetime limits inclusion.
    let (env, at) = setup();
    let (anchor, expiry) = at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, terms(), event_entry());
            let anchor = context.get_anchor_block_header().timestamp();
            (anchor, (*context).finish().expiration_timestamp)
        },
    );
    assert_eq(expiry, anchor + MAX_TX_LIFETIME);
}

#[test]
unconstrained fn a_different_pod_is_accepted() {
    // One use per POD: another POD of the same issuer with the same entry is
    // another subject.
    let (env, at) = setup();
    let first = gate_at(env, at, terms(), event_entry());
    let second = gate_at(env, at, terms(), second_pod_event());
    assert(first.subject != second.subject);
}

#[test]
unconstrained fn greater_or_equal_predicate() {
    // A tier gate (tier >= 2), at a deployment with those terms.
    let mut env = TestEnvironment::new();
    let mut t = terms();
    t.accepted.issuer = tier_entry().issuer();
    t.predicate = PREDICATE_GE;
    t.threshold = 2;
    let at = deploy(&mut env, t);
    env.mine_block();
    let claim = gate_at(env, at, t, tier_entry());
    assert_eq(claim.value, TIER);
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    // Another entry of the same POD has the same subject. The tier entry is
    // accepted by terms that pin the tier entry name and value.
    let (env, at) = setup();
    let _ = gate_at(env, at, terms(), event_entry());
    let mut tier_terms = terms();
    tier_terms.accepted.issuer = tier_entry().issuer();
    tier_terms.threshold = TIER;
    let _ = gate_bound(env, at, tier_terms, tier_entry());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn wrong_issuer_rejected() {
    // A genuine POD with `event` 42 from another issuer key.
    let (env, at) = setup();
    let _ = gate_at(env, at, terms(), other_issuer_event());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_entry_name_rejected() {
    // The entry name is part of the pinned issuer: the `tier` entry does not
    // pass for `event`, even with a threshold that its value meets.
    let (env, at) = setup();
    let mut t = terms();
    t.threshold = TIER;
    let _ = gate_bound(env, at, t, tier_entry());
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    // The other POD's tier is 1; tier gate terms require tier >= 2.
    let (env, at) = setup();
    let mut t = terms();
    t.accepted.issuer = tier_entry().issuer();
    t.predicate = PREDICATE_GE;
    t.threshold = 2;
    let _ = gate_bound(env, at, t, second_pod_tier());
}

#[test(should_fail_with = "Unbound evidence not accepted")]
unconstrained fn wrong_binding_rejected() {
    // A POD has no field that the caller chooses. Terms that require the
    // caller binding refuse it.
    let (env, at) = setup();
    let mut t = terms();
    t.allow_unbound = false;
    let _ = gate_bound(env, at, t, event_entry());
}

#[test(should_fail_with = "Undated evidence not accepted")]
unconstrained fn undated_refused_without_allow_undated() {
    let (env, at) = setup();
    let mut t = terms();
    t.allow_undated = false;
    t.max_age = 3600;
    let _ = gate_bound(env, at, t, event_entry());
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn value_not_in_the_pod_rejected() {
    // The entry proof is for 42; claiming 43 changes the leaf.
    let (env, at) = setup();
    let mut input = event_entry();
    input.value = 43;
    let mut t = terms();
    t.threshold = 43;
    let _ = gate_bound(env, at, t, input);
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn tampered_entry_proof_rejected() {
    let (env, at) = setup();
    let mut input = event_entry();
    input.siblings[0] += 1;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn bad_issuer_signature_rejected() {
    // The scalar no longer satisfies the EdDSA equation.
    let (env, at) = setup();
    let mut input = event_entry();
    input.signature_s += 1;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn content_id_of_another_pod_rejected() {
    // The second POD's content id under the base POD's signature.
    let (env, at) = setup();
    let mut input = event_entry();
    input.content_id = second_pod_event().content_id;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "POD value out of range")]
unconstrained fn negative_value_rejected() {
    // `balance` is -5: the POD hashes the field element p - 5, which would
    // read as a value near the modulus.
    let (env, at) = setup();
    let mut t = terms();
    t.accepted.issuer = negative_entry().issuer();
    t.predicate = PREDICATE_GE;
    t.threshold = 0;
    let _ = gate_bound(env, at, t, negative_entry());
}
