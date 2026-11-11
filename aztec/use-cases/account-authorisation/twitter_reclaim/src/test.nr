//! TXE tests of the Reclaim (X profile) account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash`, mines the anchor block at the claim time and
//! runs `uc_account::entrypoint` at the shell's address with the synthetic
//! Reclaim envelopes from `fixture.nr`. The account rebuilds the expected
//! context (account, action hex, username, provider hash, session) and
//! `verify_claim` checks every byte of it, the claim identifier, the
//! attestor's signature, the epoch and the 60 s freshness. The adapter pushes
//! the session nullifier and requests the expiry. No verification key, proof
//! or network is involved.
use crate::fixture::{
    ACCOUNT, ACTION, auth, NEXT_ACTION, next_same_session_context, NEXT_SAME_SESSION_CONTEXT_LEN,
    NEXT_SAME_SESSION_IDENTIFIER, NEXT_SAME_SESSION_SIGNATURE, next_session_context, NEXT_SESSION_CONTEXT_LEN,
    next_session_id, NEXT_SESSION_IDENTIFIER, NEXT_SESSION_SIGNATURE, NOW, OTHER_ATTESTOR_ADDRESS, OTHER_ATTESTOR_X,
    OTHER_ATTESTOR_Y,
};
use aztec::{protocol::traits::ToField, test::helpers::test_environment::TestEnvironment};
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let expiry = submit(env, at, TX_NONCE, auth());
    // Inclusion is limited to the claim time plus the policy's 60 s.
    assert_eq(expiry, NOW + 60);
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "already present")]
unconstrained fn session_reuse_rejected() {
    // A fresh transaction nonce with an attestation for the same session:
    // only the session nullifier rejects it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let mut input = auth();
    input.context = next_same_session_context();
    input.context_len = NEXT_SAME_SESSION_CONTEXT_LEN;
    input.identifier = NEXT_SAME_SESSION_IDENTIFIER;
    input.signature = NEXT_SAME_SESSION_SIGNATURE;
    let _ = submit(env, at, TX_NONCE + 1, input);
}

#[test]
unconstrained fn new_session_accepted() {
    // The positive control of session_reuse_rejected.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let mut input = auth();
    input.context = next_session_context();
    input.context_len = NEXT_SESSION_CONTEXT_LEN;
    input.identifier = NEXT_SESSION_IDENTIFIER;
    input.signature = NEXT_SESSION_SIGNATURE;
    input.reclaim_session_id = next_session_id();
    let _ = submit(env, at, TX_NONCE + 1, input);
}

#[test(should_fail_with = "Reclaim context mismatch")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.max_age_seconds = 61;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn wrong_issuer_rejected() {
    // Another attestor: with the policy binding skipped, the claim signature
    // does not verify under it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.attestor_x = OTHER_ATTESTOR_X;
    input.policy.attestor_y = OTHER_ATTESTOR_Y;
    input.policy.attestor_address = OTHER_ATTESTOR_ADDRESS;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Reclaim context mismatch")]
unconstrained fn other_username_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.username[0] = 117;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Reclaim claim is older than policy allows")]
unconstrained fn expired_rejected() {
    // 61 s after the claim time, past the policy's 60 s.
    let (env, at) = setup(SHELL, auth(), NOW + 61);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test]
unconstrained fn valid_at_the_maximum_age() {
    // The positive control of expired_rejected: 60 s after the claim time
    // (the policy's maximum age) the claim is still accepted.
    let (env, at) = setup(SHELL, auth(), NOW + 60);
    let expiry = submit(env, at, TX_NONCE, auth());
    assert_eq(expiry, NOW + 60);
}

#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.signature[0] = input.signature[0] ^ 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Reclaim context mismatch")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy: the signed context names this
    // account's address.
    let mut env = TestEnvironment::new();
    let _ = deploy(&mut env, SHELL, auth(), 1);
    let other = deploy(&mut env, SHELL, auth(), 2);
    env.mine_block_at(NOW);
    let _ = submit(env, other, TX_NONCE, auth());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{ACCOUNT, ACTION, action_at, auth, NEXT_ACTION, NOW, setup, SHELL, ToField, TX_NONCE};

    #[test]
    unconstrained fn fixture_is_for_this_account() {
        let (env, at) = setup(SHELL, auth(), NOW);
        let account = at.to_field();
        let action = action_at(env, at, auth(), TX_NONCE);
        let next = action_at(env, at, auth(), TX_NONCE + 1);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/reclaim.mjs --instance account-authorisation/twitter_reclaim --account
        // <account> --action <action> --next-action <next>
        assert(
            (account == ACCOUNT) & (action == ACTION) & (next == NEXT_ACTION),
            f"Fixture is not for account {account} action {action} next {next}; regenerate the fixture",
        );
    }
}
