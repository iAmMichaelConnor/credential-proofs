//! Deploy tests of the Ethereum secret-key account: they deploy its compiled
//! artifact from aztec/target (built by `test-use-cases.sh
//! --unconstrained-contracts`) at an address whose `immutables_hash` commits to
//! the policy, and call its `entrypoint` through TXE with a payload whose one
//! call is `mark` on this target. So the entrypoint's arguments cross the ABI,
//! and the dispatched call runs. The instance's own tests run the account core
//! in a private context, where TXE refuses contract calls.
//!
//! The scheme signs nothing (the secret key is the credential, and the proof of
//! the transaction binds the payload), so the credential needs no fixture bound
//! to the deployed address. No proof or network is involved.
use crate::AuthDispatchTarget;
use aztec::{
    authwit::entrypoint::{app::AppPayload, FunctionCall},
    hash::hash_args,
    oracle::nullifiers::check_nullifier_exists,
    protocol::{address::AztecAddress, traits::{Deserialize, Serialize}},
    test::helpers::test_environment::TestEnvironment,
};
use ethereum_secret_key_auth_account::EthereumSecretKeyAccount::{self, AuthInput, AuthPolicy};
use uc_account::txe::{deploy, payload, TX_NONCE};

/// The account artifact, as TXE resolves it from aztec/target.
global ACCOUNT: str<58> = "@ethereum_secret_key_auth_account/EthereumSecretKeyAccount";

/// Secret key `n` (a public test vector, not a wallet key) under the policy
/// that pins the Ethereum address of secret key 1.
fn auth(n: u8) -> AuthInput {
    let mut secret_key = [0; 32];
    secret_key[31] = n;
    AuthInput {
        policy: AuthPolicy {
            address: [126, 95, 69, 82, 9, 26, 105, 18, 93, 93, 252, 183, 184, 194, 101, 144, 41, 57, 91, 223],
        },
        secret_key,
    }
}

/// A fresh environment with the account (for the policy of `auth`) and this
/// target deployed, and a caller.
unconstrained fn setup() -> (TestEnvironment, AztecAddress, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let account = deploy(&mut env, ACCOUNT, auth(1), 1);
    let target = env.deploy("@uc_dispatch_target/AuthDispatchTarget").without_initializer();
    let caller = env.create_light_account();
    (env, account, target, caller)
}

/// Runs the account's entrypoint with `input` and the payload with
/// transaction nonce `tx_nonce` whose one call is `mark(expected_sender,
/// marker)` on `target`.
unconstrained fn dispatch(
    env: TestEnvironment,
    account: AztecAddress,
    target: AztecAddress,
    caller: AztecAddress,
    input: AuthInput,
    tx_nonce: Field,
    expected_sender: AztecAddress,
    marker: Field,
) {
    let call = AuthDispatchTarget::at(target).mark(expected_sender, marker);
    let entry = FunctionCall {
        args_hash: hash_args(call.args),
        function_selector: call.selector,
        target_address: target,
        is_public: false,
        hide_msg_sender: false,
        is_static: false,
    };
    // AppPayload's call array is private; set the first call through its serialization.
    let mut serialized = payload(tx_nonce).serialize();
    let first_call = entry.serialize();
    for i in 0..first_call.len() {
        serialized[i] = first_call[i];
    }
    let account_call = EthereumSecretKeyAccount::at(account).entrypoint(AppPayload::deserialize(serialized), input);
    env.call_private(
        caller,
        AuthDispatchTarget::at(target).execute_account(account, account_call.selector, account_call.args, call.args),
    );
}

unconstrained fn marked(env: TestEnvironment, target: AztecAddress, marker: Field) -> bool {
    env.private_context_at(target, |_| check_nullifier_exists(marker))
}

#[test]
unconstrained fn dispatched_call_runs_with_the_account_as_sender() {
    let (env, account, target, caller) = setup();
    assert(!marked(env, target, 1));
    dispatch(env, account, target, caller, auth(1), TX_NONCE, account, 1);
    assert(marked(env, target, 1));
}

#[test(should_fail_with = "Expected the account as caller")]
unconstrained fn target_expecting_another_sender_rejects() {
    let (env, account, target, caller) = setup();
    dispatch(env, account, target, caller, auth(1), TX_NONCE, caller, 1);
}

/// Another key, and a call that fails if it runs: the credential check fails
/// first, so the account dispatches nothing before authorising.
#[test(should_fail_with = "address does not match the secret key")]
unconstrained fn nothing_dispatched_before_authorisation() {
    let (env, account, target, caller) = setup();
    dispatch(env, account, target, caller, auth(2), TX_NONCE, caller, 1);
}

/// The same transaction nonce again, with another marker: the account's
/// transaction nonce nullifier is already present.
#[test(should_fail_with = "duplicate nullifier")]
unconstrained fn replay_rejected() {
    let (env, account, target, caller) = setup();
    dispatch(env, account, target, caller, auth(1), TX_NONCE, account, 1);
    dispatch(env, account, target, caller, auth(1), TX_NONCE, account, 2);
}
