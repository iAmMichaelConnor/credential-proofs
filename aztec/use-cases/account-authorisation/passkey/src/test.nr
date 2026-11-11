//! TXE tests of the passkey account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash` and runs `uc_account::entrypoint` at its
//! address with the synthetic WebAuthn assertion from `fixture.nr`.
//! `assert_valid_webauthn` checks the P-256 signature, the RP ID hash, the
//! flags, the origin and that the challenge is the action hash. Negative
//! cases mutate the valid fixture, and each names the library check that
//! rejects it; `valid` shows that the unmutated fixture passes every check.
//! No verification key, proof or network is involved.
use crate::fixture::{ACTION, auth, OTHER_KEY_X, OTHER_KEY_Y};
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "clientDataJSON challenge mismatch")]
unconstrained fn wrong_action_rejected() {
    // Another transaction nonce gives another action than the signed challenge.
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.require_user_verification = false;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "passkey signature verification failed")]
unconstrained fn wrong_issuer_rejected() {
    // The assertion under a key that the policy does not pin: with the policy
    // binding skipped, the signature check rejects it.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.key_x = OTHER_KEY_X;
    input.policy.key_y = OTHER_KEY_Y;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "passkey signature verification failed")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.signature[0] = input.signature[0] ^ 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "clientDataJSON challenge mismatch")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy has another address and so
    // another action.
    let (mut env, _) = setup(SHELL, auth(), 0);
    let other = deploy(&mut env, SHELL, auth(), 2);
    let _ = submit(env, other, TX_NONCE, auth());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{ACTION, action_at, auth, setup, SHELL, TX_NONCE};

    #[test]
    unconstrained fn fixture_action_is_the_action() {
        let (env, at) = setup(SHELL, auth(), 0);
        let action = action_at(env, at, auth(), TX_NONCE);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/passkey.mjs --instance account-authorisation/passkey --action <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
