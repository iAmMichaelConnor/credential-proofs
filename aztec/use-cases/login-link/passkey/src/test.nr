//! TXE tests of the passkey login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! WebAuthn assertion from `fixture.nr`. `assert_valid_webauthn` checks the
//! P-256 signature, the RP ID hash, the flags, the origin and that the client
//! data challenge is `timed_challenge(challenge, issued_at)`. Negative cases
//! mutate the valid fixture, and each names the library check that rejects
//! it; `valid` shows that the unmutated fixture passes every check. No verification key, proof
//! or network is involved.
use crate::fixture::{ISSUED_AT, login, MESSAGE, NOW, OTHER_KEY_X, OTHER_KEY_Y};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_passkey::{key_id, PasskeyLogin, SCHEME_PASSKEY};
use uc_login_link::{
    DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms, timed_challenge,
};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_HOLDER, SOURCE_USER_KEY, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture's relying party, one hour of
/// freshness, no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_USER_KEY,
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
                SCHEME_PASSKEY as Field,
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

/// The generated entrypoint body: `uc_login_link::link` with the assertion.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: PasskeyLogin) -> LinkClaim {
    at_shell(env, at, |context| link(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms) -> LinkClaim {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, login()),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.identity, key_id(login().key_x, login().key_y));
}

#[test]
unconstrained fn claim_has_the_user_key_labels() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_USER_KEY);
    assert_eq(claim.trust.also_authorised, 0);
    assert_eq(claim.binding.set_by, SET_BY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.expires_at, 0);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // The assertion has no expiry: inclusion is limited to issued_at + max_age.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), login());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, ISSUED_AT + 3600);
}

#[test]
unconstrained fn other_relying_party_changes_issuer_pin() {
    // The terms pin the relying party: another origin or a lowered
    // user-verification requirement gives another trust issuer.
    let mut origin = login();
    origin.origin[8] = 0x78;
    let mut uv = login();
    uv.require_user_verification = false;
    assert(origin.issuer() != login().issuer());
    assert(uv.issuer() != login().issuer());
}

#[test(should_fail_with = "clientDataJSON challenge mismatch")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge; the client data carries round
    // 0's.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "clientDataJSON challenge mismatch")]
unconstrained fn restated_issue_time_rejected() {
    // The holder signed ISSUED_AT: a later time gives another signed value
    // (the library's client-data comparison).
    let (env, at) = setup(NOW);
    let mut input = login();
    input.issued_at = ISSUED_AT + 1;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // An age (anchor time - signed issue time) of max_age + 1 is rejected.
    let (env, at) = setup(ISSUED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "Evidence issued after the anchor block")]
unconstrained fn future_issue_time_rejected() {
    let (env, at) = setup(ISSUED_AT - 1);
    let _ = link_login(env, at, login());
}

#[test(should_fail_with = "passkey signature verification failed")]
unconstrained fn wrong_key_rejected() {
    // Another key under the same relying party: the P-256 signature check
    // fails.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.key_x = OTHER_KEY_X;
    input.key_y = OTHER_KEY_Y;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "passkey signature verification failed")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = login();
    input.signature[0] = input.signature[0] ^ 1;
    let _ = link_login(env, at, input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        at_shell, ISSUED_AT, key_id, link_challenge, link_with, login, MESSAGE, NOW, setup, terms, timed_challenge,
    };

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
        let message = timed_challenge(challenge, ISSUED_AT);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/login_link.mjs --instance login-link/passkey --message <message>
        assert(message == MESSAGE, f"Fixture does not sign {message}; regenerate the fixture");
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At an age of exactly max_age the login is still fresh.
        let (env, at) = setup(ISSUED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other).identity, key_id(login().key_x, login().key_y));
    }
}
