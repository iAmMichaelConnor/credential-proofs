//! TXE tests of the Zupass login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! POD and holder signature from `fixture.nr`.
//! `zupass::assert_holder_login` checks the issuer's signature over the POD,
//! the holder entry and the holder's signature on the holder login POD
//! {`_aztec_link_v1_challenge`: challenge, `_aztec_link_v1_issued_at`:
//! issued_at}. Negative cases mutate the valid
//! fixture and say which check fails; `valid` shows that the unmutated
//! fixture passes every check. No verification key, proof or network is
//! involved.
use crate::fixture::{
    CHALLENGE, ISSUED_AT, login, NOW, OTHER_HOLDER_RX, OTHER_HOLDER_RY, OTHER_HOLDER_S, OTHER_HOLDER_X, OTHER_HOLDER_Y,
    RAW_MESSAGE, RAW_RX, RAW_RY, RAW_S,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zupass::{holder_id, SCHEME_ZUPASS, ZupassHolderLogin};
use uc_login_link::{
    DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms, timed_challenge,
};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_HOLDER, SOURCE_CERTIFIED_KEY, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture's POD issuer key and holder
/// entry, one hour of freshness, no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_CERTIFIED_KEY,
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
                SCHEME_ZUPASS as Field,
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

/// The generated entrypoint body: `uc_login_link::link` with the POD and signature.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: ZupassHolderLogin) -> LinkClaim {
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
    assert_eq(claim.identity, holder_id(login().holder_x, login().holder_y));
}

#[test]
unconstrained fn claim_has_the_certified_key_labels() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_CERTIFIED_KEY);
    assert_eq(claim.trust.also_authorised, 0);
    assert_eq(claim.binding.set_by, SET_BY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.expires_at, 0);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // The POD and the signature have no expiry: inclusion is limited to
    // issued_at + max_age.
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
unconstrained fn other_issuer_or_entry_changes_issuer_pin() {
    // The terms pin the POD issuer key and the holder entry name.
    let mut issuer = login();
    issuer.issuer_x += 1;
    let mut entry = login();
    entry.holder_name_hash += 1;
    assert(issuer.issuer() != login().issuer());
    assert(entry.issuer() != login().issuer());
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge; the holder signed round 0's.
    // The holder EdDSA check rejects it.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn restated_issue_time_rejected() {
    // The holder signed ISSUED_AT: a later time gives another login POD
    // (the holder EdDSA check).
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

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn holder_not_named_by_the_pod_rejected() {
    // Another holder key with its own valid signature on the same login POD:
    // the POD does not name it.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.holder_x = OTHER_HOLDER_X;
    input.holder_y = OTHER_HOLDER_Y;
    input.holder_rx = OTHER_HOLDER_RX;
    input.holder_ry = OTHER_HOLDER_RY;
    input.holder_s = OTHER_HOLDER_S;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn raw_timed_challenge_signature_rejected() {
    // The holder's raw signature over timed_challenge(challenge, issued_at),
    // which a bare timed-challenge relation would accept: a field-signing oracle gives
    // it. The holder EdDSA check rejects it.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.holder_rx = RAW_RX;
    input.holder_ry = RAW_RY;
    input.holder_s = RAW_S;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn bad_issuer_signature_rejected() {
    // The issuer's EdDSA check over the content id fails.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.issuer_s += 1;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn bad_signature_rejected() {
    // The holder's EdDSA check fails.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.holder_s += 1;
    let _ = link_login(env, at, input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        at_shell, CHALLENGE, holder_id, ISSUED_AT, link_challenge, link_with, login, NOW, RAW_MESSAGE, setup, terms,
        timed_challenge,
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
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/login_link.mjs --instance login-link/zupass --challenge <challenge>
        assert(challenge == CHALLENGE, f"Fixture does not sign {challenge}; regenerate the fixture");
        // The raw negative case signs the value that a bare timed-challenge relation would accept.
        assert_eq(timed_challenge(challenge, ISSUED_AT), RAW_MESSAGE);
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At an age of exactly max_age the login is still fresh.
        let (env, at) = setup(ISSUED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other).identity, holder_id(login().holder_x, login().holder_y));
    }
}
