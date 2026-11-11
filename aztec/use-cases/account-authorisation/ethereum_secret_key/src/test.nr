//! TXE tests of the Ethereum secret-key account, with the shared harness
//! (`uc_account::txe`): each test deploys the keyless shell with this
//! account's `immutables_hash` and runs `uc_account::entrypoint` at its
//! address with the synthetic secret key from `fixture.nr`. The key is the
//! credential: `assert_secret_key_for_address` derives the policy's address
//! from it, and the proof of the transaction binds the payload. There is no
//! signed action, so another payload with the same key is accepted
//! (`new_nonce_accepted`); only the transaction nonce stops a replay.
//! No verification key, proof or network is involved.
use crate::fixture::{ACTION, auth, OTHER_ADDRESS, OTHER_SECRET_KEY};
use aztec::{
    authwit::entrypoint::{app::AppPayload, FunctionCall},
    protocol::{
        abis::function_selector::FunctionSelector,
        address::AztecAddress,
        traits::{Deserialize, FromField, Serialize},
    },
    test::helpers::test_environment::PrivateContextOptions,
};
use std::test::OracleMock;
use uc_account::txe::{action_at, deploy, payload, setup, submit, submit_bound, TX_NONCE};

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

#[test]
unconstrained fn new_nonce_accepted() {
    // Key knowledge authorises each transaction that the prover builds.
    let (env, at) = setup(SHELL, auth(), 0);
    let _ = submit(env, at, TX_NONCE, auth());
    let _ = submit(env, at, TX_NONCE + 1, auth());
}

/// The private-call oracle that `PrivateContext::call_private_function_with_args_hash` uses.
global PRIVATE_CALL_ORACLE: str<29> = "aztec_prv_callPrivateFunction";

/// `payload(TX_NONCE)` with a private call to function 1 of address 7 with
/// arguments hash 1 as its first call.
fn payload_with_private_call() -> AppPayload {
    let call = FunctionCall {
        args_hash: 1,
        function_selector: FunctionSelector::from_field(1),
        target_address: AztecAddress::from_field(7),
        is_public: false,
        hide_msg_sender: false,
        is_static: false,
    };
    // AppPayload's call array is private; set the first call through its serialization.
    let mut serialized = payload(TX_NONCE).serialize();
    let first_call = call.serialize();
    for i in 0..first_call.len() {
        serialized[i] = first_call[i];
    }
    AppPayload::deserialize(serialized)
}

#[test]
unconstrained fn authorised_private_call_is_dispatched() {
    // The private-call oracle is mocked, so the called function does not run
    // (TXE refuses contract calls inside a private context). The context's
    // call requests show that the entrypoint dispatches exactly the payload's
    // call, from the account, after the transaction nonce nullifier.
    let (env, at) = setup(SHELL, auth(), 0);
    let oracle = OracleMock::mock(PRIVATE_CALL_ORACLE).returns((1000 as u32, 0));
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), |context| {
        uc_account::entrypoint(context, payload_with_private_call(), auth());
        let effects = (*context).finish();
        assert_eq(effects.private_call_requests.length, 1);
        let request = effects.private_call_requests.array[0];
        assert_eq(request.call_context.msg_sender, at);
        assert_eq(request.call_context.contract_address, AztecAddress::from_field(7));
        assert_eq(request.call_context.function_selector, FunctionSelector::from_field(1));
        assert(!request.call_context.is_static_call);
        assert_eq(request.args_hash, 1);
        assert_eq(effects.nullifiers.length, 1);
        assert(effects.nullifiers.array[0].counter < request.start_side_effect_counter);
    });
    assert_eq(oracle.times_called(), 1);
}

#[test(should_fail_with = "address does not match the secret key")]
unconstrained fn private_call_is_not_dispatched_before_authorisation() {
    // Another secret key, and the oracle is not mocked: had the entrypoint
    // dispatched the call before the credential check, TXE would fail with
    // "Contract calls are forbidden" instead.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.secret_key = OTHER_SECRET_KEY;
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), |context| {
        uc_account::entrypoint(context, payload_with_private_call(), input);
    });
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn wrong_policy_rejected() {
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.policy.address = OTHER_ADDRESS;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "address does not match the secret key")]
unconstrained fn wrong_issuer_rejected() {
    // Another secret key: its address is not the policy's.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.secret_key = OTHER_SECRET_KEY;
    let _ = submit(env, at, TX_NONCE, input);
}

#[test(should_fail_with = "address does not match the secret key")]
unconstrained fn wrong_issuer_under_bound_policy_rejected() {
    // The same check with the policy binding skipped.
    let (env, at) = setup(SHELL, auth(), 0);
    let mut input = auth();
    input.secret_key = OTHER_SECRET_KEY;
    submit_bound(env, at, TX_NONCE, input);
}

#[test]
unconstrained fn same_key_at_another_account_accepted() {
    // The key holder can use the key at every account that pins its
    // address; nothing binds the credential to one account.
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
        // The fixture signs nothing; the value only keeps the fixture shape uniform.
        let (env, at) = setup(SHELL, auth(), 0);
        let action = action_at(env, at, auth(), TX_NONCE);
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/ethereum.mjs --instance account-authorisation/ethereum_secret_key --action
        // <action>
        assert(action == ACTION, f"Fixture action is not the action {action}; regenerate the fixture");
    }
}
