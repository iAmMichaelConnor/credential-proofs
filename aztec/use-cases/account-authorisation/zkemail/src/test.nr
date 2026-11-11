//! TXE tests of the zkEmail (DKIM) account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash` and runs `uc_account::entrypoint` at its
//! address with the synthetic DKIM signature from `fixture.nr`. The account
//! rebuilds the signing input from the pinned sender, domain and selector and
//! a body `CRED-PROOF-ACTION:<action hex>`, and checks the RSA signature
//! under the pinned key. `valid` shows that the unmutated fixture
//! passes. No verification key, proof or network is involved.
use crate::fixture::{ACTION, auth, OTHER_MODULUS, OTHER_REDC};
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

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.selector[1] = 50;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_issuer_rejected() {
    // Another DKIM key: with the policy binding skipped, the signature does
    // not verify under it.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.modulus = OTHER_MODULUS;
    input.policy.redc = OTHER_REDC;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn other_sender_rejected() {
    // Another mailbox at the same domain did not send the signed mail.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.sender[0] = 98;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "sender domain mismatch")]
unconstrained fn sender_outside_service_domain_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.service_domain[0] = 116;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.signature[0] += 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
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
        // node scripts/fixtures/generators/zkemail.mjs --instance account-authorisation/zkemail --action <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
