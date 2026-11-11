//! TXE tests of the Sign-In with Ethereum login link. Each test deploys the
//! keyless `uc_terms_shell` with this instance's terms and runs `link` (the
//! call that the generated entrypoint makes) at its address with the
//! synthetic SIWE message from `fixture.nr`. The adapter rebuilds the
//! message with the link challenge as its nonce and verifies the
//! `personal_sign` signature under the address's key. Negative cases mutate
//! the valid fixture. No verification key, proof or network is involved.
use crate::fixture::{CHALLENGE, EXPIRY, EXPIRY_TIME, ISSUED_AT, login, NOW, OTHER_ADDRESS, OTHER_KEY_X, OTHER_KEY_Y};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_ethereum_siwe::{address_id, SCHEME_ETHEREUM_SIWE, SiweLogin};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_HOLDER, SOURCE_USER_KEY, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture's domain, URI and chain id,
/// one hour of freshness, no bearer logins.
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
                SCHEME_ETHEREUM_SIWE as Field,
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

/// The generated entrypoint body: `uc_login_link::link` with the message.
unconstrained fn link_login(env: TestEnvironment, at: AztecAddress, input: SiweLogin) -> LinkClaim {
    at_shell(env, at, |context| link(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms, input: SiweLogin) -> LinkClaim {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, input),
    )
}

/// The fixture with `current_time` moved to `seconds`, a time in the same
/// minute as NOW and not before it.
fn with_current_time(seconds: u64) -> SiweLogin {
    let mut input = login();
    let second = (input.current_time[17] - 48) as u64 * 10 + (input.current_time[18] - 48) as u64 + (seconds - NOW);
    assert(second < 60, "Test times stay within NOW's minute");
    input.current_time[17] = 48 + (second / 10) as u8;
    input.current_time[18] = 48 + (second % 10) as u8;
    input
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.identity, address_id(login().address));
}

#[test]
unconstrained fn claim_has_the_user_key_labels_and_signed_times() {
    let (env, at) = setup(NOW);
    let claim = link_login(env, at, login());
    assert_eq(claim.trust.source, SOURCE_USER_KEY);
    assert_eq(claim.trust.also_authorised, 0);
    assert_eq(claim.binding.set_by, SET_BY_HOLDER);
    assert_eq(claim.issued_at, ISSUED_AT);
    assert_eq(claim.expires_at, EXPIRY);
    assert(!claim.bearer);
}

#[test]
unconstrained fn inclusion_limited_by_the_expiration_time() {
    // The freshness deadline (issued at + 3600) is later than the signed
    // expiration time; inclusion is strictly before the expiration time.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), login());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, EXPIRY - 1);
}

#[test]
unconstrained fn other_relying_party_changes_issuer_pin() {
    // The terms pin the domain, URI and chain id.
    let mut domain = login();
    domain.domain[0] = 0x66;
    let mut uri = login();
    uri.uri[20] = 0x78;
    let mut chain = login();
    chain.chain_id = 10;
    assert(domain.issuer() != login().issuer());
    assert(uri.issuer() != login().issuer());
    assert(chain.issuer() != login().issuer());
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge: the rebuilt message has another
    // nonce than the signed one.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other, login());
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn other_relying_party_rejected() {
    // A message signed for example.com does not verify as one for another
    // domain (with the term binding skipped, the issuer check would refuse it
    // first).
    let (env, at) = setup(NOW);
    let mut input = login();
    input.domain[0] = 0x66;
    let mut other = terms();
    other.accepted.issuer = input.issuer();
    let _ = link_with(env, at, other, input);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // An age (anchor time - signed Issued At) of max_age + 1 is rejected,
    // while the message is unexpired.
    let (env, at) = setup(ISSUED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = link_with(env, at, other, with_current_time(ISSUED_AT + 61));
}

#[test(should_fail_with = "SIWE current time is not the anchor time")]
unconstrained fn current_time_other_than_the_anchor_rejected() {
    let (env, at) = setup(NOW + 1);
    let _ = link_login(env, at, login());
}

#[test(should_fail_with = "SIWE message expired")]
unconstrained fn expired_rejected() {
    // At the expiration time the library's `expiration_time > current_time`
    // check fails.
    let (env, at) = setup(EXPIRY);
    let mut input = login();
    input.current_time = EXPIRY_TIME;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_key_rejected() {
    // Another key and its address: the message names the other address and
    // the signature does not verify under the other key.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.address = OTHER_ADDRESS;
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "address does not match the public key")]
unconstrained fn key_of_another_address_rejected() {
    // A key that does not hash to the address: verify_personal_sign's
    // address comparison rejects it.
    let (env, at) = setup(NOW);
    let mut input = login();
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    let _ = link_login(env, at, input);
}

#[test(should_fail_with = "SIWE signature does not verify")]
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
        address_id, at_shell, CHALLENGE, ISSUED_AT, link_challenge, link_with, login, NOW, setup, terms,
        with_current_time,
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
        // node scripts/fixtures/generators/login_link.mjs --instance login-link/ethereum_siwe --challenge <challenge>
        assert(challenge == CHALLENGE, f"Fixture nonce is not {challenge}; regenerate the fixture");
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At an age of exactly max_age the login is still fresh.
        let (env, at) = setup(ISSUED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        assert_eq(link_with(env, at, other, with_current_time(ISSUED_AT + 60)).identity, address_id(login().address));
    }
}
