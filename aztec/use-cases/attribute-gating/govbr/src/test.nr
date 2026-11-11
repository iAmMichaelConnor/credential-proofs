//! TXE tests of the gov.br attribute gate. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `gate` (the call that
//! the generated entrypoint makes) at its address with the synthetic tokens
//! from `fixture.nr`, wrapped as the entrypoint wraps them
//! (`OidcAttribute { input }`). The RS256 signature and the claims are
//! verified by `govbr::verify_govbr_with_assurance`. Variants are separately signed
//! tokens; tampering cases mutate a valid one. No verification key, proof or
//! network is involved.
use crate::fixture::{
    BINDING, EXPIRY, ISSUED_AT, level_bronze, level_gold, NOW, OTHER_BINDING, other_contract, other_key_signature,
    OTHER_MODULUS_LIMBS, OTHER_REDC_PARAMS_LIMBS, other_subject, second_token, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_govbr::{GOVBR_ISSUER, GovbrIdToken, SCHEME_GOVBR};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms,
    KIND_ASSURANCE_LEVEL, PREDICATE_GE,
};
use uc_family_oidc::{bounded_bytes_hash, nonce_of, OidcAttribute, OidcLogin, OidcProviderInput, subject_id};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_IDP, ANCHOR_NONE, caller_binding, SET_BY_CLIENT, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

/// The freshness ceiling of the example terms.
global MAX_AGE: u64 = 45;

/// The instance's terms: a gov.br production login at assurance silver (rank 2) or more,
/// at most 45 s old (gov.br tokens live 60 s), bound to the caller.
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
        max_age: MAX_AGE,
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
                SCHEME_GOVBR as Field,
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
unconstrained fn gate_at(env: TestEnvironment, at: AztecAddress, t: GateTerms, input: GovbrIdToken) -> AttributeClaim {
    at_shell(env, at, |context| gate(context, t, OidcAttribute { input }))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: GovbrIdToken,
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

/// The adapter's verification of `input` at `NOW` for the fixture binding.
unconstrained fn verify_at_now(input: GovbrIdToken) -> OidcLogin {
    input.verify(nonce_of(BINDING), NOW)
}

/// `token()` with the other key (and the fixture signature).
fn other_key_token() -> GovbrIdToken {
    let mut input = token();
    input.modulus_limbs = OTHER_MODULUS_LIMBS;
    input.redc_params_limbs = OTHER_REDC_PARAMS_LIMBS;
    input
}

/// Whether the 120-bit limbs `a` (least significant first) encode a larger
/// integer than `b`: the most significant differing limb decides.
fn limbs_greater<let N: u32>(a: [u128; N], b: [u128; N]) -> bool {
    let mut greater = false;
    for i in 0..N {
        if a[i] != b[i] {
            greater = a[i] > b[i];
        }
    }
    greater
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
    assert_eq(claim.trust.issuer, token().issuer());
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR);
    assert_eq(claim.subject, subject_id(GOVBR_ISSUER, bounded_bytes_hash(token().subject)));
}

#[test]
unconstrained fn reports_the_signed_iat() {
    // The second token has the same exp and an iat one second later, so a
    // value derived from exp would not follow it.
    assert_eq(verify_at_now(token()).issued_at, ISSUED_AT);
    let later = verify_at_now(second_token());
    assert_eq(later.issued_at, ISSUED_AT + 1);
    assert_eq(later.expiry, EXPIRY);
}

#[test]
unconstrained fn inclusion_limited_by_the_login_age() {
    // min(iat + max_age, exp - 1): the terms' max_age is the tighter limit.
    let (env, at, _) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, terms(), OidcAttribute { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, ISSUED_AT + MAX_AGE);
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
unconstrained fn other_subject_accepted() {
    // One use per subject: another account at the same client is separate.
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
    // stops it. The second token verifies under the pinned key.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), token());
    let _ = gate_at(env, at, terms(), second_token());
}

#[test]
unconstrained fn other_key_verifies_its_own_signature() {
    // With its own signature over the fixture token, the other key
    // passes every check, so its limbs and Barrett parameters are well formed.
    let mut input = other_key_token();
    input.signature_b64 = other_key_signature();
    assert_eq(verify_at_now(input).subject, verify_at_now(token()).subject);
}

#[test]
unconstrained fn other_modulus_exceeds_the_fixture_modulus() {
    // The fixture signature is below the fixture modulus (`valid`), so
    // it is also below the other modulus: in field under the other key.
    assert(limbs_greater(OTHER_MODULUS_LIMBS, token().modulus_limbs));
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_key_rejected() {
    // A token that verifies under another key: the key is part of the pinned
    // issuer.
    let (env, at, _) = setup(NOW);
    let mut input = other_key_token();
    input.signature_b64 = other_key_signature();
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // The fixture token under the other key. `valid`,
    // `other_key_verifies_its_own_signature` and
    // `other_modulus_exceeds_the_fixture_modulus` show that only the PKCS#1
    // v1.5 comparison of the recovered digest can fail.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), other_key_token());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    // The fixture payload with the second token's signature, a valid
    // signature of the pinned key over another payload (`second_use_rejected`).
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.signature_b64 = second_token().signature_b64;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_binding_rejected() {
    // A token bound to the caller at the second contract.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), other_contract());
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(ISSUED_AT + MAX_AGE + 1);
    let _ = gate_at(env, at, terms(), token());
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn expired_rejected() {
    let (env, at, _) = setup(EXPIRY);
    let mut t = terms();
    t.max_age = 3600;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "OIDC token issued in the future")]
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

#[test]
unconstrained fn higher_assurance_accepted() {
    // A gold login reports rank 3, which the terms compare themselves.
    let (env, at, _) = setup(NOW);
    let claim = gate_at(env, at, terms(), level_gold());
    assert_eq(claim.value, 3);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    // Terms that require gold refuse the silver login: the gate compares the
    // reported rank, not only the pinned floor.
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = 3;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "gov.br assurance below policy")]
unconstrained fn bronze_below_the_pinned_floor_rejected() {
    // A valid bronze login under the pinned floor silver.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), level_bronze());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn lowered_minimum_level_rejected() {
    // The bronze login passes a floor of 1, but the floor is part of the
    // issuer pin: the terms refuse it.
    let (env, at, _) = setup(NOW);
    let mut input = level_bronze();
    input.minimum_level = 1;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "wrong OIDC issuer")]
unconstrained fn staging_issuer_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.staging = true;
    let _ = gate_at(env, at, terms(), input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{BINDING, binding_at, gate_at, ISSUED_AT, MAX_AGE, NOW, OTHER_BINDING, setup, terms, token};

    #[test]
    unconstrained fn fixture_nonce_is_the_caller_binding() {
        let (env, at, other) = setup(NOW);
        let binding = binding_at(env, at);
        let other_binding = binding_at(env, other);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/oidc.mjs --instance attribute-gating/govbr --binding <binding>
        // --other-binding <other>
        assert(
            (binding == BINDING) & (other_binding == OTHER_BINDING),
            f"Fixture nonces are not the caller bindings {binding} {other_binding}; regenerate the fixture",
        );
    }

    #[test]
    unconstrained fn valid_at_the_maximum_age() {
        let (env, at, _) = setup(ISSUED_AT + MAX_AGE);
        let _ = gate_at(env, at, terms(), token());
    }
}
