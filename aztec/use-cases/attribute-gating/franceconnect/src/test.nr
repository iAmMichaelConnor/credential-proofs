//! Signed FC+ assurance at keyless shells. No contract keys or proofs.
use crate::fixture::{
    assurance_3, BINDING, EXPIRY, ISSUED_AT, NOW, OTHER_BINDING, other_contract, other_key_signature, OTHER_KEY_X,
    OTHER_KEY_Y, other_subject, second_token, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_franceconnect::{FRANCECONNECT_ISSUER, FranceConnectAssuranceToken, SCHEME_FRANCECONNECT};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms,
    KIND_ASSURANCE_LEVEL, PREDICATE_EQ, PREDICATE_GE, PREDICATE_LE,
};
use uc_family_oidc::{bounded_bytes_hash, nonce_of, OidcAttribute, OidcProviderInput, subject_id};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_IDP, ANCHOR_NONE, caller_binding, SET_BY_CLIENT, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: token().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_ASSURANCE_LEVEL,
        predicate: PREDICATE_GE,
        threshold: 2,
        max_age: 90,
        allow_undated: false,
        allow_unbound: false,
        scope: 0x4643,
    }
}

fn other_terms() -> GateTerms {
    let mut t = terms();
    t.scope += 1;
    t
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_FRANCECONNECT as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, terms());
    let other = deploy(&mut env, other_terms());
    env.mine_block_at(timestamp);
    (env, at, other)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

unconstrained fn gate_at(env: TestEnvironment, at: AztecAddress, input: FranceConnectAssuranceToken) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate(context, terms(), OidcAttribute { input }),
    )
}

unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: FranceConnectAssuranceToken,
) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate_with_bound_terms(context, t, OidcAttribute { input }),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, token());
    assert_eq(claim.kind, KIND_ASSURANCE_LEVEL);
    assert_eq(claim.value, 2);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.binding.value, BINDING);
    assert_eq(claim.binding.set_by, SET_BY_CLIENT);
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR);
    assert_eq(
        claim.subject,
        subject_id(
            FRANCECONNECT_ISSUER,
            bounded_bytes_hash(token().token.subject),
        ),
    );
}

#[test]
unconstrained fn signed_three_with_minimum_two_reports_three() {
    assert_eq(assurance_3().token.minimum_acr, 2);
    let (env, at, _) = setup(NOW);
    assert_eq(gate_at(env, at, assurance_3()).value, 3);
}

#[test]
unconstrained fn equality_three_accepts_actual_three() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.predicate = PREDICATE_EQ;
    t.threshold = 3;
    assert_eq(gate_bound(env, at, t, assurance_3()).value, 3);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn equality_two_rejects_actual_three() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.predicate = PREDICATE_EQ;
    let _ = gate_bound(env, at, t, assurance_3());
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn le_two_rejects_actual_three() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.predicate = PREDICATE_LE;
    let _ = gate_bound(env, at, t, assurance_3());
}

#[test(should_fail_with = "FranceConnect+ assurance below policy")]
unconstrained fn minimum_three_rejects_signed_two() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.token.minimum_acr = 3;
    let _ = gate_at(env, at, input);
}

#[test]
unconstrained fn legacy_input_still_discloses_no_attribute() {
    let login = token().token.verify(nonce_of(BINDING), NOW);
    assert_eq(login.attribute_kind, 0);
    assert_eq(login.attribute, 0);
    let later = second_token().verify(nonce_of(BINDING), NOW);
    assert_eq(later.issued_at, ISSUED_AT + 1);
    assert_eq(later.expiry, EXPIRY);
}

#[test]
unconstrained fn fixture_nonces_are_caller_bindings() {
    let (env, at, other) = setup(NOW);
    let binding = at_shell(
        env,
        at,
        |context| caller_binding(
            DOMAIN_GATE_BINDING,
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
        ),
    );
    let other_binding = at_shell(
        env,
        other,
        |context| caller_binding(
            DOMAIN_GATE_BINDING,
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
        ),
    );
    assert(
        (binding == BINDING) & (other_binding == OTHER_BINDING),
        f"Regenerate FC+ fixture with --binding {binding} --other-binding {other_binding}",
    );
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = 3;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_binding_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, other_contract());
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, token());
    let _ = gate_at(env, at, second_token());
}

#[test]
unconstrained fn different_subject_can_use_same_scope() {
    let (env, at, _) = setup(NOW);
    let a = gate_at(env, at, token());
    let b = gate_at(env, at, other_subject());
    assert(a.subject != b.subject);
}

#[test]
unconstrained fn second_app_has_separate_binding_and_use() {
    let (env, at, other) = setup(NOW);
    let _ = gate_at(env, at, token());
    let _ = gate_bound(env, other, other_terms(), other_contract());
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(ISSUED_AT + 91);
    let _ = gate_at(env, at, token());
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn expired_rejected() {
    let (env, at, _) = setup(EXPIRY);
    let _ = gate_at(env, at, token());
}

#[test(should_fail_with = "OIDC token issued in the future")]
unconstrained fn future_token_rejected() {
    let (env, at, _) = setup(ISSUED_AT - 1);
    let _ = gate_at(env, at, token());
}

#[test]
unconstrained fn inclusion_is_limited_by_signed_time() {
    let (env, at, _) = setup(ISSUED_AT + 90);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, terms(), OidcAttribute { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, ISSUED_AT + 90);
}

#[test]
unconstrained fn inclusion_is_limited_by_token_expiry() {
    let (env, at, _) = setup(EXPIRY - 1);
    let mut t = terms();
    t.max_age = 3600;
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate_with_bound_terms(context, t, OidcAttribute { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn wrong_issuer_rejected() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.issuer += 1;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn client_operator_refused() {
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.refuse_also = ALSO_CLIENT_OPERATOR;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn wrong_key_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.token.public_key_x = OTHER_KEY_X;
    input.token.public_key_y = OTHER_KEY_Y;
    let _ = gate_at(env, at, input);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn independently_signed_other_key_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.token.public_key_x = OTHER_KEY_X;
    input.token.public_key_y = OTHER_KEY_Y;
    input.token.signature_b64 = other_key_signature();
    let _ = gate_at(env, at, input);
}
