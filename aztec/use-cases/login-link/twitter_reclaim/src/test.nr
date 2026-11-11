//! TXE tests of the Reclaim (X handle) login link. Each test deploys the
//! keyless `uc_terms_shell` with this instance's terms and runs `link` (the
//! call that the generated entrypoint makes) at its address with the
//! synthetic claim from `fixture.nr`. The adapter rebuilds the parameters
//! (template and handle) and the context (caller, challenge, handle,
//! provider hash, session); `reclaim_auth::verify_claim` checks the
//! identifier, the parameters hash, the epoch, the claim time and the
//! attestor's EIP-191 signature. Negative cases mutate the valid fixture.
//! `valid` shows that the unmutated fixture passes every check. No verification key, proof or network is involved.
use crate::fixture::{
    CALLER, CHALLENGE, CLAIMED_AT, login, NOW, OTHER_ATTESTOR_ADDRESS, OTHER_ATTESTOR_X, OTHER_ATTESTOR_Y,
    OTHER_HANDLE_IDENTIFIER, OTHER_HANDLE_PARAMETERS_HASH,
};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::ToField},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_twitter_reclaim::{handle_id, ReclaimHandleLogin, SCHEME_TWITTER_RECLAIM};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms};
use uc_trust::{
    ALSO_ATTESTOR, ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_PROVER, SOURCE_ATTESTOR, terms_commitment, TrustPolicy,
};

/// The instance's deployment terms: the fixture's attestor key and epoch,
/// provider, parameters template and provider hash, one hour of freshness,
/// no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_ATTESTOR,
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
                SCHEME_TWITTER_RECLAIM as Field,
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

/// The generated entrypoint body: `uc_login_link::link` with the claim.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: ReclaimHandleLogin) -> LinkClaim {
    at_shell(env, at, |context| link(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(
    env: TestEnvironment,
    at: AztecAddress,
    other: LinkTerms,
    input: ReclaimHandleLogin,
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
    assert_eq(claim.identity, handle_id(login().handle));
}

#[test]
unconstrained fn claim_has_the_attestor_labels() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_ATTESTOR);
    assert_eq(claim.trust.also_authorised, ALSO_ATTESTOR);
    assert_eq(claim.binding.set_by, SET_BY_PROVER);
    assert_eq(claim.issued_at, CLAIMED_AT);
    assert_eq(claim.expires_at, 0);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // The claim time is the issue time; a claim has no expiry.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), login());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, CLAIMED_AT + 3600);
}

#[test]
unconstrained fn case_variant_is_the_same_identity() {
    // One handle in another case is one identity, so it cannot link twice
    // (a claim for it would need the attestor's signature).
    let mut upper = login();
    let mut handle = upper.handle.storage();
    handle[0] = 0x41;
    handle[1] = 0x4c;
    upper.handle = BoundedVec::from_parts(handle, upper.handle.len());
    assert_eq(upper.identity(), login().identity());
}

#[test]
unconstrained fn other_attestor_or_template_changes_issuer_pin() {
    // The terms pin the attestor key and epoch, the template and the
    // provider hash.
    let mut attestor = login();
    attestor.attestor_x = OTHER_ATTESTOR_X;
    attestor.attestor_y = OTHER_ATTESTOR_Y;
    let mut template = login();
    template.parameters_suffix = BoundedVec::from_array("\"}]}".as_bytes());
    let mut provider_hash = login();
    provider_hash.provider_hash[0] = 0;
    assert(attestor.issuer() != login().issuer());
    assert(template.issuer() != login().issuer());
    assert(provider_hash.issuer() != login().issuer());
}

#[test(should_fail_with = "Reclaim claim identifier mismatch")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge, so another context: the
    // supplied identifier hint no longer matches (verify_claim's identifier
    // comparison).
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "Reclaim parameters hash mismatch")]
unconstrained fn other_handle_rejected() {
    // Hint check: another handle gives other parameters, so the supplied
    // parameters-hash hint no longer matches.
    // other_handle_with_consistent_hints_rejected reaches the signature.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.handle = BoundedVec::from_array("bob".as_bytes());
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn other_handle_with_consistent_hints_rejected() {
    // Another handle with the parameters hash and identifier that it would
    // have: the hint checks pass, and the attestor's EIP-191 signature check
    // rejects it, because the attestor signed the fixture
    // handle's identifier.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.handle = BoundedVec::from_array("bob".as_bytes());
    input.parameters_hash = OTHER_HANDLE_PARAMETERS_HASH;
    input.identifier = OTHER_HANDLE_IDENTIFIER;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Reclaim claim identifier mismatch")]
unconstrained fn other_session_rejected() {
    // Hint check: the context names the session, so another session no
    // longer matches the identifier hint.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.session = BoundedVec::from_array("session-2".as_bytes());
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // An age (anchor time - claim time) of max_age + 1 is rejected.
    let (env, at) = setup(CLAIMED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "Reclaim claim is after the current time")]
unconstrained fn claim_after_the_anchor_rejected() {
    // verify_claim's `timestamp <= now` check.
    let (env, at) = setup(CLAIMED_AT - 1);
    let _ = link_login(env, at, login());
}

#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn wrong_attestor_rejected() {
    // Another attestor key: the EIP-191 signature check fails.
    // With the term binding skipped, the issuer check would refuse it first.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.attestor_x = OTHER_ATTESTOR_X;
    input.attestor_y = OTHER_ATTESTOR_Y;
    input.attestor_address = OTHER_ATTESTOR_ADDRESS;
    let mut other = terms();
    other.accepted.issuer = input.issuer();
    let _ = link_with(env, at, other, input);
}

#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = login();
    input.signature[40] = input.signature[40] ^ 1;
    let _ = link_login(env, at, input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        at_shell, CALLER, CHALLENGE, CLAIMED_AT, handle_id, link_challenge, link_with, login, NOW, setup, terms,
        ToField,
    };

    #[test]
    unconstrained fn fixture_signs_the_challenge() {
        let (env, at) = setup(NOW);
        let (caller, challenge) = at_shell(
            env,
            at,
            |context| {
                let caller = uc_trust::msg_sender(*context);
                (
                    caller.to_field(),
                    link_challenge(
                        context.chain_id(),
                        context.version(),
                        context.this_address(),
                        caller,
                        0,
                    ),
                )
            },
        );
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/login_link.mjs --instance login-link/twitter_reclaim --caller <caller>
        // --challenge <challenge>
        assert(
            (caller == CALLER) & (challenge == CHALLENGE),
            f"Fixture context is not for caller {caller} challenge {challenge}; regenerate the fixture",
        );
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        let (env, at) = setup(CLAIMED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other, login()).identity, handle_id(login().handle));
    }
}
