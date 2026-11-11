//! TXE tests of the university (CILogon) account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash`, mines the anchor block at the fixture's `NOW`
//! and runs `uc_account::entrypoint` (the call that the generated
//! entrypoint makes) at the shell's address, with the
//! synthetic CILogon token from `fixture.nr`. `university::authorise` checks
//! the RS256 signature, the issuer `https://cilogon.org`, the audience, the
//! subject, the campus IdP (`idp`), the nonce (the action hash's hex) and
//! the token times. Negative cases mutate the valid fixture. No verification
//! key, proof or network is involved.
use crate::fixture::{ACTION, auth, EXPIRY, NOW, OTHER_MODULUS_LIMBS, OTHER_REDC_PARAMS_LIMBS};
use aztec::test::helpers::test_environment::TestEnvironment;
use uc_account::txe::{action_at, deploy, setup, submit, submit_bound, TX_NONCE};

/// The keyless shell artifact, as TXE resolves it from this package.
global SHELL: str<26> = "@uc_terms_shell/TermsShell";

#[test]
unconstrained fn valid() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let expiry = submit(env, at, TX_NONCE, auth());
    // Inclusion strictly before the token's exclusive `exp`.
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

#[test(should_fail_with = "wrong university nonce")]
unconstrained fn wrong_action_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.institutional_idp = BoundedVec::from_array("http://github.com/login/oauth/authorize".as_bytes());
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_issuer_rejected() {
    // Another well-formed key: with the policy binding skipped, the RSA
    // signature check rejects the token.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.modulus_limbs = OTHER_MODULUS_LIMBS;
    input.policy.redc_params_limbs = OTHER_REDC_PARAMS_LIMBS;
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "wrong original university idp")]
unconstrained fn other_campus_idp_rejected() {
    // A login through another campus IdP than the pinned one.
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.policy.institutional_idp = BoundedVec::from_array("urn:mace:incommon:other.edu".as_bytes());
    submit_bound(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "university token expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(SHELL, auth(), EXPIRY);
    let _ = submit(env, at, TX_NONCE, auth());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(SHELL, auth(), NOW);
    let mut input = auth();
    input.signature_b64[100] = if input.signature_b64[100] == 0x41 {
        0x42
    } else {
        0x41
    };
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "wrong university nonce")]
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
        // node scripts/fixtures/generators/oidc_account.mjs --instance account-authorisation/university --action
        // <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
