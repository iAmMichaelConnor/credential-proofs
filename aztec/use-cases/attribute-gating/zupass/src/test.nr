//! Real adapter/core tests at keyless TXE shells; no contract keys or proofs.
use crate::fixture::{BINDING, CHOICE, evidence, ISSUED_AT, NOW, other_root_entry};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::{FromField, ToField}},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zupass::{pod_id, SCHEME_ZUPASS, ZupassHolderEntry};
use uc_attribute_gate::{
    AttributeClaim, AttributeEvidence, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate_with_choice,
    gate_with_choice_with_bound_terms, GateTerms, KIND_POD_ENTRY, PREDICATE_EQ,
};
use uc_login_link::LoginLink;
use uc_trust::{ANCHOR_NONE, caller_choice_binding, SET_BY_HOLDER, SOURCE_CERTIFIED_KEY, terms_commitment, TrustPolicy};

fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_CERTIFIED_KEY,
            issuer: evidence().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_POD_ENTRY,
        predicate: PREDICATE_EQ,
        threshold: 42,
        max_age: 300,
        allow_undated: false,
        allow_unbound: false,
        scope: 0x5a50,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_ZUPASS as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, terms());
    let mut other = terms();
    other.scope += 1;
    let elsewhere = deploy(&mut env, other);
    env.mine_block_at(timestamp);
    (env, at, elsewhere)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

unconstrained fn gate_at(
    env: TestEnvironment,
    at: AztecAddress,
    input: ZupassHolderEntry,
    choice: Field,
) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate_with_choice(context, terms(), input, choice),
    )
}

unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: ZupassHolderEntry,
) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate_with_choice_with_bound_terms(context, t, input, CHOICE),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, evidence(), CHOICE);
    assert_eq(claim.kind, KIND_POD_ENTRY);
    assert_eq(claim.value, terms().threshold);
    assert_eq(
        claim.subject,
        pod_id(
            evidence().entry.issuer_x,
            evidence().entry.issuer_y,
            evidence().entry.content_id,
        ),
    );
    assert_eq(claim.binding.value, BINDING);
    assert_eq(claim.binding.set_by, SET_BY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.trust.also_authorised, 0);
}

#[test]
unconstrained fn fixture_signs_the_caller_and_choice() {
    let (env, at, _) = setup(NOW);
    let binding = at_shell(
        env,
        at,
        |context| caller_choice_binding(
            DOMAIN_GATE_BINDING,
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
            CHOICE,
        ),
    );
    assert_eq(binding, BINDING, f"Regenerate Zupass GATE fixture with --binding {binding}");
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = 43;
    let _ = gate_bound(env, at, t, evidence());
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn wrong_binding_rejected() {
    // A valid signature at one shell cannot authorize another app scope/address.
    let (env, _, elsewhere) = setup(NOW);
    let mut t = terms();
    t.scope += 1;
    let _ = gate_bound(env, elsewhere, t, evidence());
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn wrong_choice_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, evidence(), CHOICE + 1);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn changed_caller_rejected() {
    // PrivateContext has one fixed test caller. Exercise the signature against
    // the binding for a distinct caller explicitly; do not claim two TXE callers.
    let (env, at, _) = setup(NOW);
    let _ = at_shell(
        env,
        at,
        |context| {
            let actual = uc_trust::msg_sender(*context);
            let other = AztecAddress::from_field(actual.to_field() + 1);
            let binding = caller_choice_binding(
                DOMAIN_GATE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                other,
                CHOICE,
            );
            evidence().verify(context, binding)
        },
    );
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, evidence(), CHOICE);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(ISSUED_AT + 301);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test(should_fail_with = "Evidence issued after the anchor block")]
unconstrained fn future_time_rejected() {
    let (env, at, _) = setup(ISSUED_AT - 1);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test]
unconstrained fn inclusion_deadline_and_maximum_age() {
    let (env, at, _) = setup(ISSUED_AT + 300);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate_with_choice(context, terms(), evidence(), CHOICE);
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, ISSUED_AT + 300);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.holder.holder_s += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn changed_time_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.holder.issued_at += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "Different POD roots")]
unconstrained fn individually_valid_entry_from_another_root_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.entry = other_root_entry();
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "Different POD issuers")]
unconstrained fn different_issuer_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.holder.issuer_x += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn changed_numeric_entry_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.entry.value += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn changed_holder_entry_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.holder.holder_name_hash += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn wrong_issuer_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.issuer += 1;
    let _ = gate_bound(env, at, t, evidence());
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn gate_authorization_for_login_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = at_shell(
        env,
        at,
        |context| {
            let link = uc_login_link::link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                CHOICE,
            );
            assert(link != BINDING);
            evidence().holder.verify(context, link)
        },
    );
}

#[test(should_fail_with = "POD value out of range")]
unconstrained fn negative_or_oversized_numeric_value_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.entry.value = uc_adapter_zupass::MAX_ENTRY_VALUE + 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test]
unconstrained fn ticket_subject_is_not_holder_identity() {
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, evidence(), CHOICE);
    assert(claim.subject != evidence().holder.identity());
    assert(
        uc_attribute_gate::gate_nullifier(terms().scope, claim.subject)
            != uc_attribute_gate::gate_nullifier(terms().scope + 1, claim.subject),
    );
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn another_holder_key_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.holder.holder_rx = crate::fixture::OTHER_HOLDER_RX;
    input.holder.holder_ry = crate::fixture::OTHER_HOLDER_RY;
    input.holder.holder_s = crate::fixture::OTHER_HOLDER_S;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test]
unconstrained fn gate_and_login_domains_differ() {
    let (env, at, _) = setup(NOW);
    at_shell(
        env,
        at,
        |context| {
            let link = uc_login_link::link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                CHOICE,
            );
            assert(link != BINDING);
        },
    );
}
