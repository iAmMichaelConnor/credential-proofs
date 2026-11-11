//! TXE tests of the FranceConnect+ account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash`, mines the anchor block at the fixture's `NOW`
//! and runs `uc_account::entrypoint` with `OidcAccount { input }` (the call
//! that the generated entrypoint makes) at the shell's address, with the
//! synthetic ES256 token from `fixture.nr`. `franceconnect::verify_franceconnect` checks the signature,
//! the issuer, the client id, the subject, the nonce (the action hash's hex)
//! and the expiry. Negative cases mutate the valid fixture. No
//! verification key, proof or network is involved.
use crate::fixture::{ACTION, auth, EXPIRY, NOW, OTHER_KEY_X, OTHER_KEY_Y};
use aztec::test::helpers::test_environment::TestEnvironment;
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};
use uc_family_oidc::OidcAccount;

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let expiry = submit(env, at, TX_NONCE, OidcAccount { input: auth() });
    // Inclusion strictly before the token's exclusive `exp`.
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn replay_rejected() {
    // The same payload and credential again: the transaction nonce nullifier
    // (and any session nullifier) is already present.
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let _ = submit(env, at, TX_NONCE, OidcAccount { input: auth() });
    let _ = submit(env, at, TX_NONCE, OidcAccount { input: auth() });
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let _ = submit(env, at, TX_NONCE + 1, OidcAccount { input: auth() });
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let mut input = auth();
    input.policy.subject = BoundedVec::from_array("other-user".as_bytes());
    let _ = submit(env, at, TX_NONCE, OidcAccount { input });
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn wrong_issuer_rejected() {
    // Another P-256 key: with the policy binding skipped, the ES256
    // signature check rejects the token.
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let mut input = auth();
    input.policy.public_key_x = OTHER_KEY_X;
    input.policy.public_key_y = OTHER_KEY_Y;
    submit_bound(env, at, TX_NONCE, OidcAccount { input });
}

#[test(should_fail_with = "wrong OIDC audience")]
unconstrained fn wrong_audience_rejected() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let mut input = auth();
    input.policy.audience = BoundedVec::from_array("other-client".as_bytes());
    submit_bound(env, at, TX_NONCE, OidcAccount { input });
}

#[test(should_fail_with = "FranceConnect+ assurance below policy")]
unconstrained fn assurance_below_policy_rejected() {
    // A higher minimum than the token's level (the token says eidas2), with the policy
    // binding skipped.
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let mut input = auth();
    input.policy.minimum_acr = 3;
    submit_bound(env, at, TX_NONCE, OidcAccount { input });
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, EXPIRY);
    let _ = submit(env, at, TX_NONCE, OidcAccount { input: auth() });
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
    let mut input = auth();
    input.signature_b64[10] = if input.signature_b64[10] == 0x41 {
        0x42
    } else {
        0x41
    };
    let _ = submit(env, at, TX_NONCE, OidcAccount { input });
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_account_rejected() {
    // Another account with the same policy has another address and so
    // another action.
    let mut env = TestEnvironment::new();
    let _ = deploy(&mut env, SHELL, OidcAccount { input: auth() }, 1);
    let other = deploy(&mut env, SHELL, OidcAccount { input: auth() }, 2);
    env.mine_block_at(NOW);
    let _ = submit(env, other, TX_NONCE, OidcAccount { input: auth() });
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{ACTION, action_at, auth, NOW, OidcAccount, setup, SHELL, TX_NONCE};

    #[test]
    unconstrained fn fixture_action_is_the_action() {
        let (env, at) = setup(SHELL, OidcAccount { input: auth() }, NOW);
        let action = action_at(env, at, OidcAccount { input: auth() }, TX_NONCE);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/oidc_account.mjs --instance account-authorisation/franceconnect --action
        // <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
