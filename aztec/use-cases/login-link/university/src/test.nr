//! TXE tests of the university (CILogon) login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! token from `fixture.nr`. The token's RS256 signature and claims are
//! verified by `university::verify_cilogon`. Negative cases mutate the valid fixture. No
//! verification key, proof or network is involved.
use crate::fixture::{
    EXPIRY, ISSUED_AT, later_payload, later_signature, NONCE, NOW, other_key_signature, OTHER_MODULUS_LIMBS,
    OTHER_REDC_PARAMS_LIMBS, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_university::{CILOGON_ISSUER, UniversityIdToken};
use uc_family_oidc::{bounded_bytes_hash, nonce_of, OidcLink, OidcLogin, OidcProviderInput, subject_id};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkTerms};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SOURCE_IDENTITY_PROVIDER, terms_commitment, TrustPolicy};

global SCHEME: Field = 27;

/// A short freshness window for the freshness tests (below every lifetime).
global TEST_MAX_AGE: u64 = 20;

/// The instance's deployment terms: the synthetic key and client id, one
/// hour of freshness, no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: token().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: ALSO_COPY_HOLDER,
        },
        max_age: 3600,
        allow_bearer: false,
        scope: 1,
        round: 0,
    }
}

/// Deploys the shell with `terms()` and mines a block at `timestamp`, the
/// anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(DOMAIN_LINK_TERMS, SCHEME, terms().hash())),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer();
    env.mine_block_at(timestamp);
    (env, at)
}

/// Runs `f` in a private context at the deployed shell.
unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_login_link::link` with the wrapped token.
unconstrained fn link_token(env: TestEnvironment, at: AztecAddress, input: UniversityIdToken) -> Field {
    at_shell(
        env,
        at,
        |context| link(context, terms(), OidcLink { input }).identity,
    )
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms) -> Field {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, OidcLink { input: token() }).identity,
    )
}

/// The identity that a link of the fixture token returns.
fn identity() -> Field {
    subject_id(CILOGON_ISSUER, bounded_bytes_hash(token().subject))
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    assert_eq(link_token(env, at, token()), identity());
}

#[test]
unconstrained fn inclusion_limited_by_token_expiry() {
    // The token expiry asks for inclusion strictly before exp.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), OidcLink { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "wrong university audience")]
unconstrained fn wrong_audience_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut audience = input.audience.storage();
    audience[0] += 1;
    input.audience = BoundedVec::from_parts(audience, input.audience.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong university subject")]
unconstrained fn wrong_subject_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut subject = input.subject.storage();
    subject[0] += 1;
    input.subject = BoundedVec::from_parts(subject, input.subject.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong university nonce")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge; the token carries round 0's.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // A real age (anchor time - signed iat) of max_age + 1 is rejected,
    // while the token is still unexpired.
    let (env, at) = setup(ISSUED_AT + TEST_MAX_AGE + 1);
    let mut other = terms();
    other.max_age = TEST_MAX_AGE;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "university token expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(EXPIRY);
    let _ = link_token(env, at, token());
}

/// The adapter's verification of `input` at `NOW` for the fixture nonce.
unconstrained fn verify_at_now(input: UniversityIdToken) -> OidcLogin {
    input.verify(nonce_of(NONCE), NOW)
}

/// The second fixture token: the same claims and `exp`, `iat` one second
/// later, signed under the pinned key.
fn later_token() -> UniversityIdToken {
    let mut input = token();
    input.payload_b64 = later_payload();
    input.signature_b64 = later_signature();
    input
}

/// The fixture token with the other key (and the fixture signature).
fn other_key_token() -> UniversityIdToken {
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
unconstrained fn reports_the_signed_iat() {
    // The adapter reports the signed iat. The later token has the same
    // exp and an iat one second later, so a value derived from exp would not
    // follow it.
    assert_eq(verify_at_now(token()).issued_at, ISSUED_AT);
    let later = verify_at_now(later_token());
    assert_eq(later.issued_at, ISSUED_AT + 1);
    assert_eq(later.expiry, EXPIRY);
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

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // The fixture token under the other key. The tests above show that the
    // header, payload and signature pass their checks (`valid`), that the key
    // passes its checks (`other_key_verifies_its_own_signature`) and that the
    // signature is in field for it (`other_modulus_exceeds_the_fixture_modulus`).
    // Only the PKCS#1 v1.5 comparison of the recovered digest can fail.
    // `other_key_changes_issuer_pin` shows that the key also changes the
    // issuer pin.
    let (env, at) = setup(NOW);
    let _ = link_token(env, at, other_key_token());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    // The later token's signature on the fixture token: a canonical signature
    // under the pinned key, in range and in field (`reports_the_signed_iat`
    // verifies it), over another payload. Only noir_rsa's digest comparison
    // can fail.
    let (env, at) = setup(NOW);
    let mut input = token();
    input.signature_b64 = later_signature();
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong original university idp")]
unconstrained fn other_campus_rejected() {
    // The signed `idp` must name the campus identity provider of the input.
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut idp = input.institutional_idp.storage();
    idp[8] += 1;
    input.institutional_idp = BoundedVec::from_parts(idp, input.institutional_idp.len());
    let _ = link_token(env, at, input);
}

#[test]
unconstrained fn other_key_changes_issuer_pin() {
    // The terms pin the key: another key gives another trust issuer.
    let mut input = token();
    input.modulus_limbs = OTHER_MODULUS_LIMBS;
    input.redc_params_limbs = OTHER_REDC_PARAMS_LIMBS;
    assert(input.issuer() != token().issuer());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        at_shell, identity, ISSUED_AT, link_challenge, link_token, link_with, NONCE, NOW, setup, terms, TEST_MAX_AGE,
        token,
    };

    #[test]
    unconstrained fn fixture_nonce_is_the_challenge() {
        let (env, at) = setup(NOW);
        let challenge = at_shell(
            env,
            at,
            |context| link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                0,
            ),
        );
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/oidc.mjs --instance login-link/university --nonce <challenge>
        assert(challenge == NONCE, f"Fixture nonce is not the challenge {challenge}; regenerate the fixture");
    }

    #[test(should_fail_with = "already present")]
    unconstrained fn padded_subject_replay_rejected() {
        // Bytes after the subject's length do not make a second identity.
        let (env, at) = setup(NOW);
        let _ = link_token(env, at, token());
        let mut padded = token();
        let len = padded.subject.len();
        let mut storage = padded.subject.storage();
        storage[len] = 0x41;
        padded.subject = BoundedVec::from_parts(storage, len);
        let _ = link_token(env, at, padded);
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At a real age of exactly max_age the login is still fresh.
        // With stale_rejected this shows that the adapter reports the signed iat.
        let (env, at) = setup(ISSUED_AT + TEST_MAX_AGE);
        let mut other = terms();
        other.max_age = TEST_MAX_AGE;
        assert_eq(link_with(env, at, other), identity());
    }
}
