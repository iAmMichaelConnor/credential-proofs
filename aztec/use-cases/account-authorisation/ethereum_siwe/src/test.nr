//! TXE tests of the Sign-In with Ethereum account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash`, mines the anchor block at the fixture's
//! `NOW` and runs `uc_account::entrypoint` at the shell's address with the
//! synthetic EIP-4361 signature from `fixture.nr`. The adapter rebuilds the
//! message from the pinned domain, URI and chain id with the action's hex as
//! the nonce, requires `current_time` to equal the anchor time and the
//! expiration time to be later, and checks the EIP-191 signature. Each of
//! the three checks has its own message, so every negative test names the
//! check that rejects it: a changed action fails the signature check, not
//! the anchor-time check. No verification key, proof or network is
//! involved.
use crate::fixture::{ACTION, auth, EXPIRY, NOW, OTHER_ADDRESS, OTHER_KEY_X, OTHER_KEY_Y};
use aztec::test::helpers::test_environment::TestEnvironment;
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let expiry = submit(env, at, TX_NONCE, auth());
    // Inclusion strictly before the signed expiration time.
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.chain_id = 2;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_issuer_rejected() {
    // Another key with its own address: with the policy binding skipped, the
    // signature does not verify under it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.address = OTHER_ADDRESS;
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_domain_rejected() {
    // A message for another domain than the pinned one does not verify.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.domain[0] = input.policy.domain[0] + 1;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "SIWE message expired")]
unconstrained fn expired_rejected() {
    // At the signed expiration time, `current_time` (which must equal the
    // anchor time) is not before it.
    let (env, at) = setup(SHELL, auth(), EXPIRY);
    let mut input = auth();
    input.current_time = auth().expiration_time;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test]
unconstrained fn valid_one_second_before_expiry() {
    // The positive control of expired_rejected: one second before the signed
    // expiration time, with `current_time` naming that second, the same
    // signature is accepted and inclusion is limited to that second.
    let (env, at) = setup(SHELL, auth(), EXPIRY - 1);
    let mut input = auth();
    // EXPIRY - 1 = 4000000299 s.
    input.current_time = "2096-10-02T07:11:39Z".as_bytes();
    let expiry = submit(env, at, TX_NONCE, input);
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "SIWE current time is not the anchor time")]
unconstrained fn current_time_not_anchor_rejected() {
    // `current_time` names NOW, but the anchor block is one second later.
    let (env, at) = setup(SHELL, auth(), NOW + 1);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.signature[0] = input.signature[0] ^ 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "SIWE signature does not verify")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy has another address and so
    // another action.
    let mut env = TestEnvironment::new();
    let _ = deploy(&mut env, SHELL, auth(), 1);
    let other = deploy(&mut env, SHELL, auth(), 2);
    env.mine_block_at(NOW);
    let _ = submit(env, other, TX_NONCE, auth());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{ACTION, action_at, auth, NOW, setup, SHELL, TX_NONCE};

    #[test]
    unconstrained fn fixture_action_is_the_action() {
        let (env, at) = setup(SHELL, auth(), NOW);
        let action = action_at(env, at, auth(), TX_NONCE);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/ethereum.mjs --instance account-authorisation/ethereum_siwe --action
        // <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
