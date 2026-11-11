//! TXE tests of the JPKI login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms, mines the anchor block at the
//! fixture's `NOW` and runs `link` (the call that the generated entrypoint
//! makes) at its address with the synthetic chain, OCSP responses and
//! holder signature from `fixture.nr`. `jpki_auth::authorise` checks the chain to the
//! pinned root, OCSP freshness, the holder key and the holder's
//! signature over (this contract, `timed_challenge(challenge, issued_at)`,
//! session). Negative cases mutate the valid fixture and say which check fails;
//! `valid` shows that the unmutated fixture passes every check. No
//! verification key, proof or network is involved.
use crate::fixture::{ACCOUNT, ISSUED_AT, login, MESSAGE, NOW};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::ToField},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_jpki::{card_key_id, JpkiLogin, SCHEME_JPKI};
use uc_login_link::{
    DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms, timed_challenge,
};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_HOLDER, SOURCE_CERTIFIED_KEY, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture's anchor class, root and OCSP age,
/// one hour of freshness, no bearer logins.
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
                SCHEME_JPKI as Field,
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

/// The generated entrypoint body: `uc_login_link::link` with the card signature.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: JpkiLogin) -> LinkClaim {
    at_shell(env, at, |context| link(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms, input: JpkiLogin) -> LinkClaim {
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
    assert_eq(claim.identity, card_key_id(login().holder_spki_sha256));
}

#[test]
unconstrained fn claim_has_the_certified_key_labels() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_CERTIFIED_KEY);
    assert_eq(claim.trust.also_authorised, 0);
    assert_eq(claim.binding.set_by, SET_BY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
    // The earliest (exclusive) end of validity is the OCSP freshness limit:
    // this update (NOW - 60) plus the maximum OCSP age (300) plus one, before
    // the next update (NOW + 600).
    assert_eq(claim.expires_at, NOW - 60 + 300 + 1);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_ocsp_validity() {
    // The freshness deadline (issued at + 3600) is later than the OCSP
    // freshness limit; inclusion is at most this update + max OCSP age.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), login());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, NOW - 60 + 300);
}

#[test(should_fail_with = "root pin mismatch")]
unconstrained fn other_root_rejected() {
    // Another pinned root under terms that accept it: the chain does not
    // lead to it.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.root_sha256[0] = input.root_sha256[0] ^ 1;
    let mut other = terms();
    other.accepted.issuer = input.issuer();
    let _ = link_with(env, at, other, input);
}

#[test]
unconstrained fn policy_changes_issuer_pin() {
    let mut age = login();
    age.max_ocsp_age = 301;
    let mut root = login();
    root.root_sha256[0] = root.root_sha256[0] ^ 1;
    assert(age.issuer() != login().issuer());
    assert(root.issuer() != login().issuer());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge; the holder signed round 0's.
    // The holder RSA check (x509 verify_digest) fails.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn restated_issue_time_rejected() {
    // The holder signed ISSUED_AT: a later time gives another signed value
    // (the holder RSA check fails).
    let (env, at) = setup(NOW);
    let mut input = login();
    input.issued_at = ISSUED_AT + 1;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // An age (anchor time - signed issue time) of max_age + 1 is rejected,
    // while the OCSP responses are still fresh.
    let (env, at) = setup(ISSUED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "stale OCSP response")]
unconstrained fn stale_ocsp_rejected() {
    // One second after this update + max OCSP age, before the next update.
    let (env, at) = setup(NOW - 60 + 301);
    let _ = link_login(env, at, login());
}

#[test(should_fail_with = "expired OCSP response")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(NOW + 601);
    let _ = link_login(env, at, login());
}

#[test(should_fail_with = "holder key mismatch")]
unconstrained fn other_card_key_rejected() {
    // Another key hash is another identity, which this certificate does not
    // carry.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.holder_spki_sha256[0] = input.holder_spki_sha256[0] ^ 1;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    // The holder RSA check fails.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.holder_signature[0] = input.holder_signature[0] ^ 1;
    let _ = link_login(env, at, input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        ACCOUNT, at_shell, card_key_id, ISSUED_AT, link_challenge, link_with, login, MESSAGE, NOW, setup, terms,
        timed_challenge, ToField,
    };

    #[test]
    unconstrained fn fixture_signs_the_challenge() {
        let (env, at) = setup(NOW);
        let account = at.to_field();
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
        // python3 scripts/fixtures/generators/x509.py --instance login-link/jpki --account <account> --message
        // <message>
        assert(
            (account == ACCOUNT) & (message == MESSAGE),
            f"Fixture is not for account {account} message {message}; regenerate the fixture",
        );
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        let (env, at) = setup(ISSUED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other, login()).identity, card_key_id(login().holder_spki_sha256));
    }
}
