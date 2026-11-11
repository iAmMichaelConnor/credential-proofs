//! TXE tests of the Zupass account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash` and runs `uc_account::entrypoint` at its
//! address with the synthetic POD and holder approval from `fixture.nr`.
//! `assert_holder_approval` checks the issuer's signature on the POD root,
//! the membership of the `owner` entry that names the holder key, and the
//! holder's signature on the approval POD (account, action, expires) whose
//! root the circuit recomputes. The signature checks fail with "EdDSA
//! signature mismatch" and the entry check with "POD entry mismatch". `valid`
//! shows that the unmutated fixture passes. No verification key, proof or
//! network is involved.
use crate::fixture::{
    ACCOUNT, ACTION, auth, EXPIRES, OTHER_ACCOUNT_RX, OTHER_ACCOUNT_RY, OTHER_ACCOUNT_S, OTHER_HOLDER_RX,
    OTHER_HOLDER_RY, OTHER_HOLDER_S, OTHER_HOLDER_X, OTHER_HOLDER_Y, OTHER_ISSUER_X, OTHER_ISSUER_Y, RAW_ACTION_RX,
    RAW_ACTION_RY, RAW_ACTION_S,
};
use aztec::protocol::traits::ToField;
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), 0);
    let expiry = submit(env, at, TX_NONCE, auth());
    // The protocol's 24-hour limit from the anchor is the earlier bound here.
    assert(expiry < EXPIRES);
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test]
unconstrained fn valid_near_expiry() {
    // Within 24 hours of the expiry, the approval sets the transaction
    // expiration: the last second before its exclusive expiry.
    let (env, at) = setup(SHELL, auth(), EXPIRES - 3600);
    let expiry = submit(env, at, TX_NONCE, auth());
    assert_eq(expiry, EXPIRES - 1);
}

#[test]
unconstrained fn valid_in_last_second() {
    let (env, at) = setup(SHELL, auth(), EXPIRES - 1);
    let expiry = submit(env, at, TX_NONCE, auth());
    assert_eq(expiry, EXPIRES - 1);
}

#[test(should_fail_with = "Holder approval expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(SHELL, auth(), EXPIRES);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn later_expiry_rejected() {
    // The holder signed EXPIRES, not a later expiry.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.expires += 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn raw_action_signature_rejected() {
    // The holder's raw signature over the action field.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.holder_rx = RAW_ACTION_RX;
    input.holder_ry = RAW_ACTION_RY;
    input.holder_s = RAW_ACTION_S;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn approval_for_other_account_rejected() {
    // The holder approved this action for account + 1.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.holder_rx = OTHER_ACCOUNT_RX;
    input.holder_ry = OTHER_ACCOUNT_RY;
    input.holder_s = OTHER_ACCOUNT_S;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.content_id += 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn wrong_issuer_rejected() {
    // Another issuer key: with the policy binding skipped, the POD signature
    // does not verify under it.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.issuer_x = OTHER_ISSUER_X;
    input.policy.issuer_y = OTHER_ISSUER_Y;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn holder_not_named_by_the_pod_rejected() {
    // A valid approval signature by a key that the POD does not name.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.holder_x = OTHER_HOLDER_X;
    input.holder_y = OTHER_HOLDER_Y;
    input.holder_rx = OTHER_HOLDER_RX;
    input.holder_ry = OTHER_HOLDER_RY;
    input.holder_s = OTHER_HOLDER_S;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
unconstrained fn bad_holder_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.holder_s += 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "POD entry mismatch")]
unconstrained fn wrong_entry_path_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.siblings[0] += 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "EdDSA signature mismatch")]
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
    use super::{ACCOUNT, ACTION, action_at, auth, setup, SHELL, ToField, TX_NONCE};

    #[test]
    unconstrained fn fixture_is_for_this_account() {
        let (env, at) = setup(SHELL, auth(), 0);
        let account = at.to_field();
        let action = action_at(env, at, auth(), TX_NONCE);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/zupass.mjs --instance account-authorisation/zupass --account <account>
        // --action <action>
        assert(
            (account == ACCOUNT) & (action == ACTION),
            f"Fixture is not for account {account} action {action}; regenerate the fixture",
        );
    }
}
