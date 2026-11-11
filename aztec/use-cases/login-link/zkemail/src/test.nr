//! TXE tests of the zkEmail login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! login email from `fixture.nr`. The adapter rebuilds the body
//! `CRED-PROOF-LINK:<challenge hex>\r\n` and the DKIM signing input and
//! verifies the RSA signature with `zkemail::dkim::RSAPubkey`. Negative cases
//! mutate the valid fixture and say which check fails; `valid` shows
//! that the unmutated fixture passes every check. No verification key, proof
//! or network is involved.
use crate::fixture::{CHALLENGE, login, NOW, OTHER_MODULUS, OTHER_REDC, SIGNED_AT};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zkemail::{mailbox, SCHEME_ZKEMAIL, ZkemailLoginEmail};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms};
use uc_trust::{
    ALSO_COPY_HOLDER, ALSO_IDP, ALSO_MAIL_OPERATOR, ANCHOR_NONE, SET_BY_SENDER, SOURCE_IDENTITY_PROVIDER,
    terms_commitment, TrustPolicy,
};

/// The instance's deployment terms: the fixture's DKIM key, domain and
/// selector, one hour of freshness, no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: login().issuer(),
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
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_LINK_TERMS,
                SCHEME_ZKEMAIL as Field,
                terms().hash(),
            )),
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

/// The generated entrypoint body: `uc_login_link::link` with the email.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: ZkemailLoginEmail) -> LinkClaim {
    at_shell(env, at, |context| link(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(
    env: TestEnvironment,
    at: AztecAddress,
    other: LinkTerms,
    input: ZkemailLoginEmail,
) -> LinkClaim {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, input),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.identity, mailbox(login().sender));
}

#[test]
unconstrained fn claim_has_the_mail_labels() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_IDENTITY_PROVIDER);
    assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_MAIL_OPERATOR);
    assert_eq(claim.binding.set_by, SET_BY_SENDER);
    assert_eq(claim.issued_at, SIGNED_AT);
    assert_eq(claim.expires_at, 0);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // DKIM t= is the issue time; the profile has no x= expiry.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), login());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, SIGNED_AT + 3600);
}

#[test]
unconstrained fn other_key_changes_issuer_pin() {
    // The terms pin the DKIM key, domain and selector.
    let mut key = login();
    key.modulus = OTHER_MODULUS;
    key.redc = OTHER_REDC;
    assert(key.issuer() != login().issuer());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge, so another body hash in the
    // rebuilt signing input; noir_rsa's signature check fails.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // An age (anchor time - DKIM t=) of max_age + 1 is rejected.
    let (env, at) = setup(SIGNED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn other_sender_rejected() {
    // Another mailbox of the same domain: the signed From differs
    // (noir_rsa's signature check fails).
    let (env, at) = setup(NOW);
    let mut input = login();
    input.sender = BoundedVec::from_array("bob@mail.example".as_bytes());
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Sender domain differs from the DKIM domain")]
unconstrained fn sender_outside_the_dkim_domain_rejected() {
    let (env, at) = setup(NOW);
    let mut input = login();
    input.sender = BoundedVec::from_array("alice@other.example".as_bytes());
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // Another well-formed key: the RSA check fails. With the
    // term binding skipped, the issuer check would refuse it first.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.modulus = OTHER_MODULUS;
    input.redc = OTHER_REDC;
    let mut other = terms();
    other.accepted.issuer = input.issuer();
    let _ = link_with(env, at, other, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = login();
    input.signature[3] += 1;
    let _ = link_login(env, at, input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{at_shell, CHALLENGE, link_challenge, link_with, login, mailbox, NOW, setup, SIGNED_AT, terms};

    #[test]
    unconstrained fn fixture_signs_the_challenge() {
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
        // node scripts/fixtures/generators/login_link.mjs --instance login-link/zkemail --challenge <challenge>
        assert(challenge == CHALLENGE, f"Fixture body does not carry {challenge}; regenerate the fixture");
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        let (env, at) = setup(SIGNED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other, login()).identity, mailbox(login().sender));
    }
}
