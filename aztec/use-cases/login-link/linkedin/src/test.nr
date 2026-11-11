//! TXE tests of the LinkedIn bearer login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! LinkedIn token from `fixture.nr`. The token's RS256-4096 signature,
//! issuer, audience, subject and times are verified by
//! `linkedin::verify_linkedin_bearer_times`. The token has no nonce, so no
//! challenge is bound: the claim is bearer, and the terms must accept bearer
//! logins and must not refuse the identity provider, the client operator or
//! copy holders. Negative cases mutate the valid fixture. No verification
//! key, proof or network is involved.
use crate::fixture::{
    EXPIRY, ISSUED_AT, later_payload, later_signature, NOW, other_key_signature, OTHER_MODULUS_LIMBS,
    OTHER_REDC_PARAMS_LIMBS, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_linkedin::{LINKEDIN_ISSUER, LinkedInIdToken};
use uc_family_oidc::{bounded_bytes_hash, OidcBearerLink, OidcLink, OidcLogin, OidcProviderInput, subject_id};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_with_bound_terms, LinkClaim, LinkTerms};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_COPY_HOLDER, ALSO_IDP, ANCHOR_NONE, MAX_BEARER_AGE, SET_BY_NONE,
    SOURCE_IDENTITY_PROVIDER, terms_commitment, TrustPolicy,
};

global SCHEME: Field = 44;

/// A short freshness window for the freshness tests.
global TEST_MAX_AGE: u64 = 20;

/// The instance's deployment terms: the synthetic key and client id, one
/// hour of freshness, bearer logins accepted (the only kind LinkedIn gives),
/// no co-authority refused.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: token().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        max_age: 3600,
        allow_bearer: true,
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
unconstrained fn link_token(env: TestEnvironment, at: AztecAddress, input: LinkedInIdToken) -> LinkClaim {
    at_shell(
        env,
        at,
        |context| link(context, terms(), OidcBearerLink { input }),
    )
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms) -> Field {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, OidcBearerLink { input: token() }).identity,
    )
}

/// The inclusion deadline that a link under `other` requests.
unconstrained fn requested_expiry(env: TestEnvironment, at: AztecAddress, other: LinkTerms) -> u64 {
    at_shell(
        env,
        at,
        |context| {
            let _ = link_with_bound_terms(context, other, OidcBearerLink { input: token() });
            (*context).finish().expiration_timestamp
        },
    )
}

/// The identity that a link of the fixture token returns.
fn identity() -> Field {
    subject_id(LINKEDIN_ISSUER, bounded_bytes_hash(token().subject))
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let claim = link_token(env, at, token());
    assert_eq(claim.identity, identity());
    // The claim says what the token is: bearer, bound to nothing, and
    // producible by LinkedIn, the client operator and any copy holder.
    assert(claim.bearer);
    assert_eq(claim.binding.set_by, SET_BY_NONE);
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR | ALSO_COPY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
}

#[test(should_fail_with = "Bearer login not accepted")]
unconstrained fn bearer_refused_without_allow_bearer() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.allow_bearer = false;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn bearer_refused_when_copy_holders_refused() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.accepted.refuse_also = ALSO_COPY_HOLDER;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "LinkedIn tokens carry no nonce")]
unconstrained fn challenge_link_rejected() {
    // The token cannot serve as a challenge-bound login: `OidcLink` asks it
    // to carry the challenge, and the adapter refuses any nonce.
    let (env, at) = setup(NOW);
    let _ = at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, terms(), OidcLink { input: token() }),
    );
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

#[test]
unconstrained fn bearer_ceiling_limits_inclusion() {
    // Terms that allow a day get MAX_BEARER_AGE (4 hours) from the signed
    // iat; the token itself lives a day, so its expiry is not the limit.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.max_age = 86400;
    assert(ISSUED_AT + MAX_BEARER_AGE < EXPIRY - 1);
    assert_eq(requested_expiry(env, at, other), ISSUED_AT + MAX_BEARER_AGE);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn older_than_bearer_ceiling_rejected() {
    // A token older than MAX_BEARER_AGE by its signed iat is refused even
    // under terms that allow a day, while it is still unexpired.
    let (env, at) = setup(ISSUED_AT + MAX_BEARER_AGE + 1);
    let mut other = terms();
    other.max_age = 86400;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "wrong LinkedIn audience")]
unconstrained fn wrong_audience_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut audience = input.audience.storage();
    audience[0] += 1;
    input.audience = BoundedVec::from_parts(audience, input.audience.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong LinkedIn subject")]
unconstrained fn wrong_subject_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut subject = input.subject.storage();
    subject[0] += 1;
    input.subject = BoundedVec::from_parts(subject, input.subject.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "LinkedIn token expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(EXPIRY);
    let _ = link_token(env, at, token());
}

/// The adapter's verification of `input` at `NOW` with no nonce (bearer).
unconstrained fn verify_at_now(input: LinkedInIdToken) -> OidcLogin {
    input.verify(BoundedVec::new(), NOW)
}

/// The second fixture token: the same claims and `exp`, `iat` one second
/// later, signed under the pinned key.
fn later_token() -> LinkedInIdToken {
    let mut input = token();
    input.payload_b64 = later_payload();
    input.signature_b64 = later_signature();
    input
}

/// The fixture token with the other key (and the fixture signature).
fn other_key_token() -> LinkedInIdToken {
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

#[test]
unconstrained fn other_key_changes_issuer_pin() {
    // The terms pin the key: another key gives another trust issuer.
    let mut input = token();
    input.modulus_limbs = OTHER_MODULUS_LIMBS;
    input.redc_params_limbs = OTHER_REDC_PARAMS_LIMBS;
    assert(input.issuer() != token().issuer());
}

#[test]
unconstrained fn other_challenge_still_links() {
    // Bearer: the token binds no challenge. Under another round (another
    // challenge, as for another caller) the same token still links.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    assert_eq(link_with(env, at, other), identity());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{identity, ISSUED_AT, link_with, setup, terms, TEST_MAX_AGE};

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At a real age of exactly max_age the login is still fresh. With
        // stale_rejected this shows that the adapter reports the signed iat.
        let (env, at) = setup(ISSUED_AT + TEST_MAX_AGE);
        let mut other = terms();
        other.max_age = TEST_MAX_AGE;
        assert_eq(link_with(env, at, other), identity());
    }
}
