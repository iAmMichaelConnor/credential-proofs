//! TXE tests of the University (CILogon) attribute gate. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `gate` (the call that
//! the generated entrypoint makes) at its address with the synthetic tokens
//! from `fixture.nr`, wrapped as the entrypoint wraps them
//! (`OidcAttribute { input }`). The RS256 signature and the claims are
//! verified by `university::verify_cilogon_with_affiliation`. Variants are separately signed
//! tokens; tampering cases mutate a valid one. No verification key, proof or
//! network is involved.
use crate::fixture::{
    BINDING, EXPIRY, ISSUED_AT, no_affiliation, NOW, OTHER_BINDING, other_contract, other_key_signature,
    OTHER_MODULUS_LIMBS, OTHER_REDC_PARAMS_LIMBS, other_subject, second_token, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_university::{affiliation_attribute, CILOGON_ISSUER, SCHEME_UNIVERSITY, UniversityAffiliationToken};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_BINDING, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms, KIND_AFFILIATION,
    PREDICATE_EQ,
};
use uc_family_oidc::{bounded_bytes_hash, nonce_of, OidcAttribute, OidcLogin, OidcProviderInput, subject_id};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_IDP, ANCHOR_NONE, caller_binding, SET_BY_CLIENT, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

/// The freshness ceiling of the example terms.
global MAX_AGE: u64 = 300;

/// The instance's terms: a CILogon login through the pinned campus identity provider whose signed
/// `affiliation` lists `student@example.edu`,
/// at most 300 s old, bound to the caller.
fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: token().token.issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_AFFILIATION,
        predicate: PREDICATE_EQ,
        threshold: affiliation_attribute(entry("student@example.edu")),
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
                SCHEME_UNIVERSITY as Field,
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
    input: UniversityAffiliationToken,
) -> AttributeClaim {
    at_shell(env, at, |context| gate(context, t, OidcAttribute { input }))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    input: UniversityAffiliationToken,
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
unconstrained fn verify_at_now(input: UniversityAffiliationToken) -> OidcLogin {
    input.verify(nonce_of(BINDING), NOW)
}

/// `token()` with the other key (and the fixture signature).
fn other_key_token() -> UniversityAffiliationToken {
    let mut input = token();
    input.token.modulus_limbs = OTHER_MODULUS_LIMBS;
    input.token.redc_params_limbs = OTHER_REDC_PARAMS_LIMBS;
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
    assert_eq(claim.kind, KIND_AFFILIATION);
    assert_eq(claim.value, affiliation_attribute(entry("student@example.edu")));
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.binding.value, BINDING);
    assert_eq(claim.binding.set_by, SET_BY_CLIENT);
    assert_eq(claim.trust.issuer, token().token.issuer());
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR);
    assert_eq(claim.subject, subject_id(CILOGON_ISSUER, bounded_bytes_hash(token().token.subject)));
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
    input.token.signature_b64 = other_key_signature();
    assert_eq(verify_at_now(input).subject, verify_at_now(token()).subject);
}

#[test]
unconstrained fn other_modulus_exceeds_the_fixture_modulus() {
    // The fixture signature is below the fixture modulus (`valid`), so
    // it is also below the other modulus: in field under the other key.
    assert(limbs_greater(OTHER_MODULUS_LIMBS, token().token.modulus_limbs));
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_key_rejected() {
    // A token that verifies under another key: the key is part of the pinned
    // issuer.
    let (env, at, _) = setup(NOW);
    let mut input = other_key_token();
    input.token.signature_b64 = other_key_signature();
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
    input.token.signature_b64 = second_token().token.signature_b64;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "wrong university nonce")]
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

#[test(should_fail_with = "university token expired")]
unconstrained fn expired_rejected() {
    let (env, at, _) = setup(EXPIRY);
    let mut t = terms();
    t.max_age = 3600;
    let _ = gate_bound(env, at, t, token());
}

#[test(should_fail_with = "university token issued in future")]
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

/// An affiliation entry at the input capacity.
fn entry<let N: u32>(text: str<N>) -> BoundedVec<u8, 128> {
    let bytes = text.as_bytes();
    let mut value = BoundedVec::new();
    for i in 0..N {
        value.push(bytes[i]);
    }
    value
}

/// `token()` presenting another affiliation entry.
fn presenting<let N: u32>(text: str<N>) -> UniversityAffiliationToken {
    let mut input = token();
    input.affiliation = entry(text);
    input
}

#[test]
unconstrained fn other_listed_entry_accepted_by_its_terms() {
    // The token lists member@ too; terms on member@ accept it.
    let (env, at, _) = setup(NOW);
    let mut t = terms();
    t.threshold = affiliation_attribute(entry("member@example.edu"));
    let claim = gate_bound(env, at, t, presenting("member@example.edu"));
    assert_eq(claim.value, t.threshold);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    // A listed entry that the terms do not name.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), presenting("member@example.edu"));
}

#[test(should_fail_with = "missing asserted university affiliation")]
unconstrained fn unlisted_affiliation_rejected() {
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), presenting("faculty@example.edu"));
}

#[test(should_fail_with = "missing asserted university affiliation")]
unconstrained fn affiliation_prefix_rejected() {
    // No substring match: a prefix of a listed entry is not an entry.
    let (env, at, _) = setup(NOW);
    let _ = gate_bound(env, at, terms(), presenting("student@example"));
}

#[test(should_fail_with = "missing asserted university affiliation")]
unconstrained fn joined_entries_rejected() {
    // The whole signed list is not one entry.
    let (env, at, _) = setup(NOW);
    let _ = gate_bound(
        env,
        at,
        terms(),
        presenting("member@example.edu;student@example.edu"),
    );
}

#[test(should_fail_with = "empty university affiliation policy")]
unconstrained fn empty_affiliation_rejected() {
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.affiliation = BoundedVec::new();
    let _ = gate_bound(env, at, terms(), input);
}

#[test(should_fail_with = "missing selected JSON member")]
unconstrained fn token_without_affiliation_rejected() {
    // A valid login whose token carries no affiliation claim.
    let (env, at, _) = setup(NOW);
    let _ = gate_at(env, at, terms(), no_affiliation());
}

#[test(should_fail_with = "wrong original university idp")]
unconstrained fn other_campus_rejected() {
    // The signed `idp` names the fixture campus; the input cannot name another.
    let (env, at, _) = setup(NOW);
    let mut input = token();
    input.token.institutional_idp = BoundedVec::from_parts([104; 256], 20);
    let _ = gate_bound(env, at, terms(), input);
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
        // node scripts/fixtures/generators/oidc.mjs --instance attribute-gating/university --binding <binding>
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
