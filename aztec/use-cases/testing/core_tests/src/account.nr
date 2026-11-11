use crate::{deploy_with_immutables, in_context, requested_expiry};
use aztec::{
    authwit::entrypoint::app::AppPayload,
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::TestEnvironment,
};
use uc_account::{AccountAuthorisation, AccountGrant, action_hash, entrypoint, entrypoint_with_bound_policy};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, SET_BY_HOLDER, SET_BY_NONE, SOURCE_IDENTITY_PROVIDER, SOURCE_PLATFORM,
    SOURCE_USER_KEY, Trust,
};

global SCHEME: u32 = 9001;
global SESSION_TAG: Field = 0x5e55;

/// A dummy key-control credential. `signed_action` stands in for the value a
/// real signature covers; the dummy adapter reports it without checking it,
/// so the tests exercise the core's binding rule rather than an adapter's.
pub struct DummySigner {
    pub key: Field,
    pub signed_action: Field,
    pub session: Field,
    pub expires: u64,
    pub source: u8,
    pub set_by: u8,
    pub also: u8,
    /// Fails `check_input` when set.
    pub bad_input: bool,
}

impl AccountAuthorisation for DummySigner {
    let SCHEME: u32 = 9001;

    fn policy_hash(self) -> Field {
        poseidon2_hash([self.key])
    }

    fn check_input(self) {
        assert(!self.bad_input, "Dummy input check failed");
    }

    fn authorise(self, _context: &mut PrivateContext, _action: Field) -> AccountGrant {
        AccountGrant {
            trust: Trust {
                source: self.source,
                issuer: 0,
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: self.also,
            },
            binding: Binding { value: self.signed_action, set_by: self.set_by },
            expiration_timestamp: if self.expires == 0 {
                Option::none()
            } else {
                Option::some(self.expires - 1)
            },
            session_nullifier: if self.session == 0 {
                Option::none()
            } else {
                Option::some(poseidon2_hash([SESSION_TAG, self.session]))
            },
        }
    }
}

fn payload(tx_nonce: Field) -> AppPayload {
    let mut payload: AppPayload = std::mem::zeroed();
    payload.tx_nonce = tx_nonce;
    payload
}

fn signer() -> DummySigner {
    DummySigner {
        key: 1,
        signed_action: 0,
        session: 0,
        expires: 0,
        source: SOURCE_USER_KEY,
        set_by: SET_BY_HOLDER,
        also: 0,
        bad_input: false,
    }
}

/// Signs the action of `signed` and submits `submitted`. With `at`, the
/// public `entrypoint` runs at that deployed account; without it,
/// `entrypoint_with_bound_policy` runs at the TXE default address.
unconstrained fn submit_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    auth: DummySigner,
    signed: AppPayload,
    submitted: AppPayload,
) -> u64 {
    in_context(
        env,
        at,
        |context| {
            let mut auth = auth;
            auth.signed_action = action_hash(context, SCHEME as Field, signed);
            if at.is_some() {
                entrypoint(context, submitted, auth);
            } else {
                entrypoint_with_bound_policy(context, submitted, auth);
            }
            requested_expiry(context)
        },
    )
}

unconstrained fn submit(env: TestEnvironment, auth: DummySigner, signed: AppPayload, submitted: AppPayload) -> u64 {
    submit_at(env, Option::none(), auth, signed, submitted)
}

/// Deploys an account whose address commits to the policy of `auth`, as
/// `bind_policy` expects: `immutables_hash = Poseidon2([SCHEME, policy_hash])`.
unconstrained fn deploy_account(env: &mut TestEnvironment, auth: DummySigner) -> AztecAddress {
    deploy_with_immutables(env, poseidon2_hash([SCHEME as Field, auth.policy_hash()]))
}

#[test]
unconstrained fn account_valid_accepted() {
    let env = TestEnvironment::new();
    let _ = submit(env, signer(), payload(1), payload(1));
}

#[test(should_fail_with = "already present")]
unconstrained fn account_replay_rejected() {
    let env = TestEnvironment::new();
    let _ = submit(env, signer(), payload(1), payload(1));
    let _ = submit(env, signer(), payload(1), payload(1));
}

#[test(should_fail_with = "Evidence bound to another action")]
unconstrained fn account_wrong_action_rejected() {
    let env = TestEnvironment::new();
    let _ = submit(env, signer(), payload(1), payload(2));
}

#[test]
unconstrained fn account_new_nonce_accepted() {
    let env = TestEnvironment::new();
    let _ = submit(env, signer(), payload(1), payload(1));
    let _ = submit(env, signer(), payload(2), payload(2));
}

#[test(should_fail_with = "Dummy input check failed")]
unconstrained fn account_input_check_rejected() {
    let env = TestEnvironment::new();
    let mut auth = signer();
    auth.bad_input = true;
    let _ = submit(env, auth, payload(1), payload(1));
}

#[test(should_fail_with = "already present")]
unconstrained fn account_session_replay_rejected() {
    let env = TestEnvironment::new();
    let mut auth = signer();
    auth.session = 77;
    let _ = submit(env, auth, payload(1), payload(1));
    let _ = submit(env, auth, payload(2), payload(2));
}

#[test]
unconstrained fn account_expiry_limits_inclusion() {
    // Stale account evidence is rejected at inclusion: the core passes the
    // credential's expiry to the transaction. TXE does not run that rollup
    // check, so the test reads the requested expiry.
    let env = TestEnvironment::new();
    let mut auth = signer();
    auth.expires = env.last_block_timestamp() + 60;
    let expiry = submit(env, auth, payload(1), payload(1));
    assert_eq(expiry, auth.expires - 1);
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
unconstrained fn account_payment_evidence_rejected() {
    let env = TestEnvironment::new();
    let mut auth = signer();
    auth.source = SOURCE_PLATFORM;
    let _ = submit(env, auth, payload(1), payload(1));
}

#[test(should_fail_with = "Bearer evidence cannot authorise an account")]
unconstrained fn account_bearer_evidence_rejected() {
    let env = TestEnvironment::new();
    let mut auth = signer();
    auth.source = SOURCE_IDENTITY_PROVIDER;
    auth.set_by = SET_BY_NONE;
    auth.also = ALSO_COPY_HOLDER;
    let _ = submit(env, auth, payload(1), payload(1));
}

// The public `entrypoint` at a deployed account. It repeats the
// body of `entrypoint_with_bound_policy` for bytecode stability, so these tests
// mirror the tests above to catch drift between the two bodies.

#[test]
unconstrained fn entrypoint_valid_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_account(&mut env, signer());
    let _ = submit_at(env, Option::some(at), signer(), payload(1), payload(1));
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn entrypoint_wrong_policy_rejected() {
    // A credential for another key than the one the account commits to.
    let mut env = TestEnvironment::new();
    let at = deploy_account(&mut env, signer());
    let mut other = signer();
    other.key = 2;
    let _ = submit_at(env, Option::some(at), other, payload(1), payload(1));
}

#[test(should_fail_with = "already present")]
unconstrained fn entrypoint_replay_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_account(&mut env, signer());
    let _ = submit_at(env, Option::some(at), signer(), payload(1), payload(1));
    let _ = submit_at(env, Option::some(at), signer(), payload(1), payload(1));
}

#[test(should_fail_with = "Evidence bound to another action")]
unconstrained fn entrypoint_wrong_action_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_account(&mut env, signer());
    let _ = submit_at(env, Option::some(at), signer(), payload(1), payload(2));
}

#[test]
unconstrained fn entrypoint_new_nonce_accepted() {
    // Mirror of account_new_nonce_accepted.
    let mut env = TestEnvironment::new();
    let at = deploy_account(&mut env, signer());
    let _ = submit_at(env, Option::some(at), signer(), payload(1), payload(1));
    let _ = submit_at(env, Option::some(at), signer(), payload(2), payload(2));
}

#[test(should_fail_with = "Dummy input check failed")]
unconstrained fn entrypoint_input_check_rejected() {
    // `check_input` runs after the policy binding: the policy is the bound one.
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    auth.bad_input = true;
    let at = deploy_account(&mut env, auth);
    let _ = submit_at(env, Option::some(at), auth, payload(1), payload(1));
}

#[test(should_fail_with = "already present")]
unconstrained fn entrypoint_session_replay_rejected() {
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    auth.session = 77;
    let at = deploy_account(&mut env, auth);
    let _ = submit_at(env, Option::some(at), auth, payload(1), payload(1));
    let _ = submit_at(env, Option::some(at), auth, payload(2), payload(2));
}

#[test]
unconstrained fn entrypoint_expiry_limits_inclusion() {
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    let at = deploy_account(&mut env, auth);
    auth.expires = env.last_block_timestamp() + 60;
    let expiry = submit_at(env, Option::some(at), auth, payload(1), payload(1));
    assert_eq(expiry, auth.expires - 1);
}

#[test]
unconstrained fn entrypoint_expired_credential_not_rejected_at_the_anchor_block() {
    // The account core passes the credential expiry to the
    // transaction but does not compare it with the anchor block (bytecode
    // stability). An expired credential executes here and requests an expiry
    // before the anchor block, so it is rejected no later than inclusion.
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    let at = deploy_account(&mut env, auth);
    let now = env.last_block_timestamp();
    auth.expires = now - 10;
    let expiry = submit_at(env, Option::some(at), auth, payload(1), payload(1));
    assert(expiry < now);
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
unconstrained fn entrypoint_payment_evidence_rejected() {
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    auth.source = SOURCE_PLATFORM;
    let at = deploy_account(&mut env, auth);
    let _ = submit_at(env, Option::some(at), auth, payload(1), payload(1));
}

#[test(should_fail_with = "Bearer evidence cannot authorise an account")]
unconstrained fn entrypoint_bearer_evidence_rejected() {
    let mut env = TestEnvironment::new();
    let mut auth = signer();
    auth.source = SOURCE_IDENTITY_PROVIDER;
    auth.set_by = SET_BY_NONE;
    auth.also = ALSO_COPY_HOLDER;
    let at = deploy_account(&mut env, auth);
    let _ = submit_at(env, Option::some(at), auth, payload(1), payload(1));
}
