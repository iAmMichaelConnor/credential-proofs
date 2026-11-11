//! TXE tests of the Singpass attribute gate. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `gate` (the call that
//! the generated entrypoint makes) at its address with the synthetic tokens
//! from `fixture.nr`, wrapped as the entrypoint wraps them
//! (`OidcAttribute { input }`). The ES256 signature and the claims are
//! verified by `singpass_auth`. Wrong-term cases use separately signed tokens;
//! tampering cases mutate a valid one. No verification key, proof or network
//! is involved.
use crate::fixture::{
    assurance_3, BINDING, EXPIRY, ISSUED_AT, NOW, OTHER_BINDING, other_contract, other_key, OTHER_KEY_X, OTHER_KEY_Y,
    other_subject, second_token, staging, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_singpass::{SCHEME_SINGPASS, SINGPASS_ISSUER, SingpassIdToken};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms,
    KIND_ASSURANCE_LEVEL, PREDICATE_GE,
};
use uc_family_oidc::{bounded_bytes_hash, OidcAttribute, subject_id};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_IDP, ANCHOR_NONE, caller_binding, SET_BY_CLIENT, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

/// The instance's terms: a Singpass production login at assurance level 2
/// or more (MFA), at most 300 s old, bound to the caller.
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
        max_age: 300,
        allow_undated: false,
        allow_unbound: false,
        scope: 0x5149,
    }
}

/// A second contract: the same terms in another app scope.
fn other_contract_terms() -> GateTerms {
    let mut t = terms();
    t.scope = 0x514a;
    t
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_SINGPASS as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

/// Deploys the shell with `terms()` and `other_contract_terms()`, and mines a
/// block at `timestamp`, the anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, terms());
    let other = deploy(&mut env, other_contract_terms());
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

/// The generated entrypoint body: `uc_attribute_gate::gate`.
unconstrained fn gate_at(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: SingpassIdToken,
) -> AttributeClaim {
    at_shell(env, at, |context| gate(context, t, OidcAttribute { input }))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: SingpassIdToken,
) -> AttributeClaim {
    at_shell(
        env,
        at,
        |context| gate_with_bound_terms(context, t, OidcAttribute { input }),
    )
}

unconstrained fn binding_at(env: TestEnvironment, at: AztecAddress) -> Field {
    at_shell(
        env,
        at,
        |context| caller_binding(
            DOMAIN_GATE_BINDING,
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
        ),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, terms(), token());
    assert_eq(claim.kind, KIND_ASSURANCE_LEVEL);
    assert_eq(claim.value, 2);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.binding.value, BINDING);
    assert_eq(claim.binding.set_by, SET_BY_CLIENT);
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR);
    assert_eq(claim.subject, subject_id(SINGPASS_ISSUER, bounded_bytes_hash(token().subject)));
}

#[test]
unconstrained fn inclusion_limited_by_the_login_age() {
    // min(iat + max_age, exp - 1): the terms' 300 s is the tighter limit.
    let (env, at, _) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, terms(), OidcAttribute { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, ISSUED_AT + 300);
}

#[test]
unconstrained fn inclusion_limited_by_the_token_expiry() {
    // With a longer max_age the token's own exp limits inclusion.
    let (env, at, _) = setup(NOW);
    let mut long = terms();
    long.max_age = 3600;
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate_with_bound_terms(context, long, OidcAttribute { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, EXPIRY - 1);
}

#[test]
unconstrained fn higher_assurance_accepted() {
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, terms(), assurance_3());
    assert_eq(claim.value, 3);
}

#[test]
unconstrained fn other_subject_accepted() {
    // One use per subject: another person at the same client is separate.
    let (env, at, _) = setup(NOW);
    let first = gate_at(env, at, terms(), token());
    let second = gate_at(env, at, terms(), other_subject());
    assert(first.subject != second.subject);
}

#[test]
unconstrained fn other_contract_token_valid_there() {
    // The binding names the contract: the token bound at the second contract
    // works there.
    let (env, _, other) = setup(NOW);
    let _ = gate_at(env, other, other_contract_terms(), other_contract());
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    // A second, genuine login of the same subject: the subject nullifier
    // stops it.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), token());
    let _ = gate_at(env, at, terms(), second_token());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_key_rejected() {
    // A valid token under another key: the key is part of the pinned issuer.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), other_key());
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn wrong_key_rejected() {
    // The token of the pinned key, presented with another key.
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn staging_token_rejected() {
    // Staging accepts assurance 1; its issuer differs from production.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), staging());
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    // Terms that require assurance 3 refuse the level-2 login.
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = 3;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_binding_rejected() {
    // A token bound to the caller at the second contract.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), other_contract());
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(ISSUED_AT + 301);
    let _ = gate_at(env, at, terms(), token());
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn expired_rejected() {
    let (env, at, _) = setup(EXPIRY);
    let mut t = terms();
    t.max_age = 3600;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "Singpass token issued in future")]
unconstrained fn token_after_the_anchor_block_rejected() {
    let (env, at, _) = setup(ISSUED_AT - 1);
    let _ = gate_at(env, at, terms(), token());
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn client_operator_refused() {
    // Terms can refuse evidence that the OIDC client operator could make.
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.accepted.refuse_also = ALSO_CLIENT_OPERATOR;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn tampered_signature_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    let mut storage = input.signature_b64.storage();
    storage[10] = if storage[10] == 0x41 { 0x42 } else { 0x41 };
    input.signature_b64 = BoundedVec::from_parts(storage, input.signature_b64.len());
    let _ = gate_at(env, at, terms(), input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{BINDING, binding_at, gate_at, ISSUED_AT, NOW, OTHER_BINDING, setup, terms, token};

    #[test]
    unconstrained fn fixture_nonce_is_the_caller_binding() {
        let (env, at, other) = setup(NOW);
        let binding = binding_at(env, at);
        let other_binding = binding_at(env, other);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/singpass.mjs --instance attribute-gating/singpass --binding <binding>
        // --other-binding <other>
        assert(
            (binding == BINDING) & (other_binding == OTHER_BINDING),
            f"Fixture nonces are not the caller bindings {binding} {other_binding}; regenerate the fixture",
        );
    }

    #[test]
    unconstrained fn valid_at_the_maximum_age() {
        let (env, at, _) = setup(ISSUED_AT + 300);
        let _ = gate_at(env, at, terms(), token());
    }
}
