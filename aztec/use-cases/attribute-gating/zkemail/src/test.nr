//! Real adapter/core tests at keyless TXE shells; no contract keys or proofs.
use crate::fixture::{BINDING, CHOICE, evidence, link_purpose, NOW, OTHER_MODULUS, OTHER_REDC, SIGNED_AT};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::{FromField, ToField}},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zkemail::{bytes_hash, mailbox, SCHEME_ZKEMAIL, ZkemailDomainEmail};
use uc_attribute_gate::{
    AttributeClaim, AttributeEvidence, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate_with_choice,
    gate_with_choice_with_bound_terms, GateTerms, KIND_EMAIL_DOMAIN, PREDICATE_EQ,
};
use uc_trust::{
    ALSO_IDP, ALSO_MAIL_OPERATOR, ANCHOR_NONE, caller_choice_binding, SET_BY_SENDER, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

fn bounded<let N: u32, let M: u32>(text: str<M>) -> BoundedVec<u8, N> {
    BoundedVec::from_array(text.as_bytes())
}

fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: evidence().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_EMAIL_DOMAIN,
        predicate: PREDICATE_EQ,
        threshold: bytes_hash(bounded::<64, 12>("mail.example")),
        max_age: 300,
        allow_undated: false,
        allow_unbound: false,
        scope: 0x454d,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_ZKEMAIL as Field,
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
    input: ZkemailDomainEmail,
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
    input: ZkemailDomainEmail,
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
    assert_eq(claim.kind, KIND_EMAIL_DOMAIN);
    assert_eq(claim.value, terms().threshold);
    assert_eq(claim.subject, mailbox(evidence().email.sender));
    assert_eq(claim.binding.value, BINDING);
    assert_eq(claim.binding.set_by, SET_BY_SENDER);
    assert_eq(claim.issued_at, SIGNED_AT);
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_MAIL_OPERATOR);
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
    assert_eq(binding, BINDING, f"Regenerate zkEmail GATE fixture with --binding {binding}");
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = bytes_hash(bounded::<64, 13>("other.example"));
    let _ = gate_bound(env, at, t, evidence());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_binding_rejected() {
    // A valid signature at one shell cannot authorize another app scope/address.
    let (env, _, elsewhere) = setup(NOW);
    let mut t = terms();
    t.scope += 1;
    let _ = gate_bound(env, elsewhere, t, evidence());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_choice_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, evidence(), CHOICE + 1);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
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

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn link_purpose_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, link_purpose(), CHOICE);
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, evidence(), CHOICE);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(SIGNED_AT + 301);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test(should_fail_with = "Evidence issued after the anchor block")]
unconstrained fn future_time_rejected() {
    let (env, at, _) = setup(SIGNED_AT - 1);
    let _ = gate_at(env, at, evidence(), CHOICE);
}

#[test]
unconstrained fn inclusion_deadline_and_maximum_age() {
    let (env, at, _) = setup(SIGNED_AT + 300);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate_with_choice(context, terms(), evidence(), CHOICE);
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, SIGNED_AT + 300);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.email.signature[0] += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_time_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.email.signed_at += 1;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_domain_rejected() {
    // Both names remain strictly aligned, so this reaches the signature check.
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.email.domain = bounded("other.example");
    input.email.sender = bounded("alice@other.example");
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "Sender domain differs from the DKIM domain")]
unconstrained fn unaligned_from_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.email.sender = bounded("alice@other.example");
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = evidence();
    input.email.modulus = OTHER_MODULUS;
    input.email.redc = OTHER_REDC;
    let _ = gate_at(env, at, input, CHOICE);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn wrong_issuer_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.issuer += 1;
    let _ = gate_bound(env, at, t, evidence());
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn mail_operator_refused() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.refuse_also = ALSO_MAIL_OPERATOR;
    let _ = gate_bound(env, at, t, evidence());
}
