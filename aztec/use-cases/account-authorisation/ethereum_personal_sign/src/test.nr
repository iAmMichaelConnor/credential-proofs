//! TXE tests of the Ethereum personal_sign account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash`, mines the anchor block at the fixture's `NOW`
//! (or at the time the test names) and runs `uc_account::entrypoint` at its
//! address with the synthetic EIP-191 signature from `fixture.nr`. The
//! signature covers `Poseidon2([APPROVAL_DOMAIN, action, deadline])`.
//! `verify_personal_sign` recovers nothing: it checks the signature under the
//! supplied key and that the key's address is the policy's. Negative cases
//! mutate the valid fixture. The account asserts the library's bool and the
//! deadline with their own messages, and the library names its address
//! comparison, so each test names the check that rejects it. TXE does not
//! apply the rollup's expiry check; the tests compare the expiry that the
//! account requests. No verification key, proof or network is involved.
use crate::fixture::{ACTION, auth, DEADLINE, NOW, OTHER_ADDRESS, OTHER_KEY_X, OTHER_KEY_Y};
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let expiry = submit(env, at, TX_NONCE, auth());
    // Inclusion no later than the signed deadline.
    assert_eq(expiry, DEADLINE);
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "Ethereum approval deadline has passed")]
unconstrained fn expired_rejected() {
    // The anchor block is one second after the signed deadline.
    let (env, at) = setup(SHELL, auth(), DEADLINE + 1);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test]
unconstrained fn valid_at_deadline() {
    // The positive control of expired_rejected: with the anchor block at the
    // deadline itself, the same signature is accepted and inclusion is
    // limited to that second.
    let (env, at) = setup(SHELL, auth(), DEADLINE);
    let expiry = submit(env, at, TX_NONCE, auth());
    assert_eq(expiry, DEADLINE);
}

#[test(should_fail_with = "Ethereum signature does not verify")]
unconstrained fn extended_deadline_rejected() {
    // The signature covers the deadline: a later one does not verify.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.deadline = DEADLINE + 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Ethereum signature does not verify")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.address = OTHER_ADDRESS;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Ethereum signature does not verify")]
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

#[test(should_fail_with = "address does not match the public key")]
unconstrained fn key_of_another_address_rejected() {
    // The policy's address with another key: the address check rejects it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Ethereum signature does not verify")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.signature[0] = input.signature[0] ^ 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "Ethereum signature does not verify")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy has another address and so
    // another action.
    let (mut env, _) = setup(SHELL, auth(), NOW);
    let other = deploy(&mut env, SHELL, auth(), 2);
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
        // node scripts/fixtures/generators/ethereum.mjs --instance account-authorisation/ethereum_personal_sign
        // --action <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
