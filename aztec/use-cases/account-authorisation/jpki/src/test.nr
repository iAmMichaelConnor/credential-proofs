//! TXE tests of the JpkiAccount, with the shared harness (`uc_account::txe`):
//! each test deploys the keyless shell with this account's
//! `immutables_hash`, mines the anchor block at the fixture's `NOW` and runs
//! `uc_account::entrypoint` at the shell's address with the synthetic chain,
//! OCSP responses and card signature from `fixture.nr`. The library checks
//! the chain to the pinned root, the holder key pin, OCSP freshness and the
//! holder's signature over the challenge (account, action, session). The
//! adapter pushes the session nullifier and requests the expiry. Negative
//! cases mutate the valid fixture. No verification key, proof or network is involved.
use crate::fixture::{
    ACCOUNT, ACTION, auth, NEXT_ACTION, NEXT_SAME_SESSION_SIGNATURE, NEXT_SESSION, NEXT_SESSION_SIGNATURE, NOW,
};
use aztec::{protocol::traits::ToField, test::helpers::test_environment::TestEnvironment};
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let expiry = submit(env, at, TX_NONCE, auth());
    // Inclusion is limited by the OCSP responses (next update NOW + 600).
    assert((expiry >= NOW) & (expiry < NOW + 600));
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
    // A fresh transaction nonce, signed with the same session: only the
    // session nullifier rejects it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let mut input = auth();
    input.holder_signature = NEXT_SAME_SESSION_SIGNATURE;
    let _ = submit(env, at, TX_NONCE + 1, input);
}

#[test]
unconstrained fn new_session_accepted() {
    // The positive control of session_reuse_rejected.
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE, auth());
    let mut input = auth();
    input.session = NEXT_SESSION;
    input.holder_signature = NEXT_SESSION_SIGNATURE;
    let _ = submit(env, at, TX_NONCE + 1, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.max_ocsp_age = 301;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "root pin mismatch")]
unconstrained fn wrong_issuer_rejected() {
    // Another pinned root: with the policy binding skipped, the chain does
    // not lead to it.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.root_sha256[0] = input.policy.root_sha256[0] ^ 1;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "expired OCSP response")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW + 601);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.holder_signature[0] = input.holder_signature[0] ^ 1;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy: the card challenge names this
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
        // python3 scripts/fixtures/generators/x509.py --instance account-authorisation/jpki --account <account>
        // --action <action> --next-action <next>
        assert(
            (account == ACCOUNT) & (action == ACTION) & (next == NEXT_ACTION),
            f"Fixture is not for account {account} action {action} next {next}; regenerate the fixture",
        );
    }
}
