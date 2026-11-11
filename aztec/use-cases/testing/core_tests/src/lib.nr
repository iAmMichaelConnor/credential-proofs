//! TXE tests of the generic use-case cores with dummy evidence types.
//!
//! Each dummy type implements a core trait the way an adapter will, with a
//! Poseidon2 tag standing in for the scheme's signature or proof. The tests
//! run the generic rules inside a TXE private context: valid evidence is
//! accepted, and replay, stale evidence, wrong terms and wrong trust are
//! rejected.
//!
//! The public core functions (`settle`, `gate`, `once`, `link`, `on_event`,
//! `entrypoint`, `bind_terms`, `bind_policy`) run in a private context at a
//! deployed `uc_terms_shell` instance whose `immutables_hash` the test
//! chooses, so the term binding reads a real contract instance. That contract
//! has no private or public function, so TXE needs no verification key: no
//! key generation takes place.
//!
//! TXE executes the private functions and its world state rejects duplicate
//! nullifiers. It does not prove, and it does not apply the rollup's
//! transaction-expiry check, so the expiry tests read the expiry that the
//! core requested (`PrivateContext::finish().expiration_timestamp`).
mod account;
mod login_link;
mod attribute_gate;
mod uniqueness;
mod payment;
mod event;
mod terms;

use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};

/// Deploys a `uc_terms_shell` instance whose address commits to `immutables_hash`.
pub unconstrained fn deploy_with_immutables(env: &mut TestEnvironment, immutables_hash: Field) -> AztecAddress {
    env
        .deploy_opts(DeployOptions::new().with_immutables_hash(immutables_hash), "@uc_terms_shell/TermsShell")
        .without_initializer()
}

/// Runs `f` in a private context at `at`, or at the TXE default address.
pub unconstrained fn in_context<Env, T>(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    let mut opts = PrivateContextOptions::new();
    if at.is_some() {
        opts = opts.at_contract_address(at.unwrap());
    }
    env.private_context_opts(opts, f)
}

/// The inclusion deadline that the private context requests at the end.
pub unconstrained fn requested_expiry(context: &mut PrivateContext) -> u64 {
    (*context).finish().expiration_timestamp
}
