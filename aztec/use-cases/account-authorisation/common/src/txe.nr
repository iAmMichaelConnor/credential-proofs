//! TEST ONLY: TXE helpers of the account-authorisation instance tests
//! (`uc_account::txe`). They are unconstrained and no contract calls them.
//!
//! An instance test deploys the keyless `uc_terms_shell` (no private or
//! public function, so TXE needs no verification key) at an address whose
//! `immutables_hash` commits to the instance's policy, then runs
//! `uc_account::entrypoint`, the call that the generated entrypoint makes,
//! in a private context at that address. The action hash therefore binds the
//! shell's address, and the fixtures sign that action. No proof is made.
//!
//! TXE does not apply the rollup's transaction-expiry check; `submit`
//! returns the expiry that the private context requests instead.
//!
//! `shell` is the shell artifact as TXE resolves it from the package under
//! test (`<path>@<package>/<contract>`); the instance test passes it, so this
//! crate names no checkout path. `submit_bound` runs the public
//! `entrypoint_with_bound_policy`, which skips the policy binding, to reach a
//! credential check under a policy that the address does not commit to.
use crate::{AccountAuthorisation, action_hash, entrypoint, entrypoint_with_bound_policy};
use aztec::{
    authwit::entrypoint::app::AppPayload,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};

/// The transaction nonce of the payload that the fixtures sign.
pub global TX_NONCE: Field = 123;

/// An empty payload with `tx_nonce`.
pub fn payload(tx_nonce: Field) -> AppPayload {
    let mut payload: AppPayload = std::mem::zeroed();
    payload.tx_nonce = tx_nonce;
    payload
}

/// Deploys the shell with `salt` at an address that commits to the policy of
/// `input`: `immutables_hash = Poseidon2([SCHEME, policy_hash])`.
pub unconstrained fn deploy<A, let N: u32>(
    env: &mut TestEnvironment,
    shell: str<N>,
    input: A,
    salt: Field,
) -> AztecAddress
where
    A: AccountAuthorisation,
{
    env
        .deploy_opts(
            DeployOptions::new().with_salt(salt).with_immutables_hash(poseidon2_hash([
                A::SCHEME as Field,
                input.policy_hash(),
            ])),
            shell,
        )
        .without_initializer()
}

/// A fresh environment with the account of `input` deployed (salt 1) and,
/// when `now` is not 0, a block mined at `now`, the anchor of the next call.
pub unconstrained fn setup<A, let N: u32>(shell: str<N>, input: A, now: u64) -> (TestEnvironment, AztecAddress)
where
    A: AccountAuthorisation,
{
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, shell, input, 1);
    if now != 0 {
        env.mine_block_at(now);
    }
    (env, at)
}

/// The action hash of `payload(tx_nonce)` at `at`, which the fixtures sign.
pub unconstrained fn action_at<A>(env: TestEnvironment, at: AztecAddress, _input: A, tx_nonce: Field) -> Field
where
    A: AccountAuthorisation,
{
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), |context| {
        action_hash(context, A::SCHEME as Field, payload(tx_nonce))
    })
}

/// The generated entrypoint body at `at`. Returns the requested expiry.
pub unconstrained fn submit<A>(env: TestEnvironment, at: AztecAddress, tx_nonce: Field, input: A) -> u64
where
    A: AccountAuthorisation,
{
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), |context| {
        entrypoint(context, payload(tx_nonce), input);
        (*context).finish().expiration_timestamp
    })
}

/// The rules after the policy binding, at `at`: a credential check under a
/// policy that the address does not commit to.
pub unconstrained fn submit_bound<A>(env: TestEnvironment, at: AztecAddress, tx_nonce: Field, input: A)
where
    A: AccountAuthorisation,
{
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), |context| {
        entrypoint_with_bound_policy(context, payload(tx_nonce), input)
    })
}
