//! Account-authorisation core (use case U1): "the account owner approved this
//! exact payload". Only category 1 to 4 evidence can reach this core.
//!
//! Bytecode stability. An account's address commits to its class id, so a
//! bytecode change gives the same policy another address. The Brillig part
//! of the bytecode changes when the account path gains a function boundary
//! around the credential check, or uses a Noir global whose value is not
//! already in the program's Brillig global pool (for example a `u8` global
//! equal to 0); the ACIR follows the order of the checks. `entrypoint` is
//! therefore one function body, the account path uses literal trust values
//! (pinned to the `uc_trust` constants by unit tests), `check_input` runs
//! before the action hash, and adapters may apply their session nullifier and
//! expiry inside `authorise` (see the trait). Adapters use the constructors
//! below, or `comptime { uc_trust::X }` for any other constant.
use aztec::{
    authwit::{account::compute_tx_nullifier, entrypoint::app::AppPayload},
    context::PrivateContext,
    oracle::get_contract_instance::get_contract_instance,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Hash, ToField}},
};
use uc_trust::{Binding, Trust};

mod tests;
pub mod txe;

/// Domain of the action hash.
pub global ENTRYPOINT_DOMAIN: Field = comptime { poseidon2_hash_bytes("MIKE_AUTH_ENTRYPOINT_V1".as_bytes()) };

/// What an adapter proves about one authorisation.
pub struct AccountGrant {
    /// `source` must be 1 to 4 and `also_authorised` must not include copy holders.
    pub trust: Trust,
    /// `value` must equal the action hash; `set_by` must be HOLDER, CLIENT, SENDER or PROVER.
    pub binding: Binding,
    /// The last inclusive inclusion timestamp the credential allows, passed
    /// to `set_expiration_timestamp`. The adapter derives it from the signed
    /// expiry (for example `exp - 1` for an exclusive JWT `exp`). The core
    /// does not compare it with the anchor block (bytecode stability), so an
    /// expired credential executes and is rejected no later than inclusion.
    pub expiration_timestamp: Option<u64>,
    /// A replay key for the credential's own session, pushed as given. The
    /// adapter domain-separates it.
    pub session_nullifier: Option<Field>,
}

/// Implemented by an adapter's input struct for each category 1 to 4 scheme.
pub trait AccountAuthorisation {
    /// The scheme id, unique per scheme (it enters the action hash and the policy commitment).
    let SCHEME: u32;
    /// Poseidon2 of the serialised account policy.
    fn policy_hash(self) -> Field;
    /// Checks of the bound policy and the input that need no action hash,
    /// run after the policy binding and before the action hash. The default
    /// checks nothing (the Reclaim account checks its identifiers here).
    fn check_input(self) {}
    /// Verifies the credential over `action` and reports what it proved. The
    /// adapter reports as `binding.value` only a value that its credential
    /// check bound. An adapter may push its session nullifier and request
    /// its expiry here itself, before the end of its credential check; its
    /// grant then reports neither.
    fn authorise(self, context: &mut PrivateContext, action: Field) -> AccountGrant;
}

/// The account entrypoint rules, written once: bind the policy to the
/// account address, run `check_input`, compute the action hash, verify the
/// credential, admit the grant, apply its session nullifier and expiry, then
/// consume the transaction nonce and execute the payload.
pub fn entrypoint<A>(context: &mut PrivateContext, payload: AppPayload, auth: A)
where
    A: AccountAuthorisation,
{
    bind_policy(context, A::SCHEME as Field, auth.policy_hash());
    // The rest is identical to `entrypoint_with_bound_policy`. It is not a
    // call to it, because that function boundary changes the Brillig layout.
    auth.check_input();
    let action = action_hash(context, A::SCHEME as Field, payload);
    let grant = auth.authorise(context, action);
    assert_admissible(grant, action);
    if grant.session_nullifier.is_some() {
        context.push_nullifier_unsafe(grant.session_nullifier.unwrap_unchecked());
    }
    if grant.expiration_timestamp.is_some() {
        context.set_expiration_timestamp(grant.expiration_timestamp.unwrap_unchecked());
    }
    execute(context, payload);
}

/// As `entrypoint`, for a caller that has already authenticated the policy
/// in `auth`. Calling it without that check lets any credential authorise.
pub fn entrypoint_with_bound_policy<A>(context: &mut PrivateContext, payload: AppPayload, auth: A)
where
    A: AccountAuthorisation,
{
    auth.check_input();
    let action = action_hash(context, A::SCHEME as Field, payload);
    let grant = auth.authorise(context, action);
    assert_admissible(grant, action);
    if grant.session_nullifier.is_some() {
        context.push_nullifier_unsafe(grant.session_nullifier.unwrap_unchecked());
    }
    if grant.expiration_timestamp.is_some() {
        context.set_expiration_timestamp(grant.expiration_timestamp.unwrap_unchecked());
    }
    execute(context, payload);
}

/// Use-case admissibility (INV-10b): only category 1 to 4 evidence that binds
/// this action authorises an account. Payment, document, chain and bearer
/// evidence is rejected as the adapter labels it. The check reads the labels
/// that the adapter reports: an adapter that bolts a separately enrolled key
/// onto a credential and reports `SOURCE_USER_KEY` with `SET_BY_HOLDER`
/// passes it. The no-bolt-on rule is an adapter review rule, not a
/// constraint.
pub fn assert_admissible(grant: AccountGrant, action: Field) {
    // Literals: SOURCE_USER_KEY = 1 to SOURCE_ATTESTOR = 4; ALSO_COPY_HOLDER = 32;
    // SET_BY_HOLDER = 1, SET_BY_CLIENT = 2, SET_BY_SENDER = 3, SET_BY_PROVER = 4.
    let source = grant.trust.source;
    assert((source >= 1) & (source <= 4), "Evidence cannot authorise an account");
    assert((grant.trust.also_authorised & 32) == 0, "Bearer evidence cannot authorise an account");
    let set_by = grant.binding.set_by;
    assert((set_by == 1) | (set_by == 2) | (set_by == 3) | (set_by == 4), "Account evidence must bind a chosen value");
    assert(grant.binding.value == action, "Evidence bound to another action");
}

/// Trust of a category 1 credential: the user's own key.
pub fn user_key_trust() -> Trust {
    Trust { source: 1, issuer: 0, anchor_kind: 0, anchor: 0, finality: 0, also_authorised: 0 }
}

/// Trust of a category 2 credential: a user key that `issuer` certified.
pub fn certified_key_trust(issuer: Field) -> Trust {
    Trust { source: 2, issuer, anchor_kind: 0, anchor: 0, finality: 0, also_authorised: 0 }
}

/// Trust of a category 3 credential: an identity provider or mail domain
/// asserts a login or message. `also_authorised` names who else can produce
/// it (for OIDC: `ALSO_IDP | ALSO_CLIENT_OPERATOR` = 3; for DKIM:
/// `ALSO_IDP | ALSO_MAIL_OPERATOR` = 5).
pub fn identity_provider_trust(issuer: Field, also_authorised: u8) -> Trust {
    Trust { source: 3, issuer, anchor_kind: 0, anchor: 0, finality: 0, also_authorised }
}

/// Trust of a category 4 credential: an attestor (`ALSO_ATTESTOR` = 8).
pub fn attestor_trust(issuer: Field) -> Trust {
    Trust { source: 4, issuer, anchor_kind: 0, anchor: 0, finality: 0, also_authorised: 8 }
}

/// The action, bound by the holder's key.
pub fn holder_bound(value: Field) -> Binding {
    Binding { value, set_by: 1 }
}

/// The action, bound in a nonce that the OIDC client picks.
pub fn client_bound(value: Field) -> Binding {
    Binding { value, set_by: 2 }
}

/// The action, bound in a body that the mailbox sender writes.
pub fn sender_bound(value: Field) -> Binding {
    Binding { value, set_by: 3 }
}

/// The action, bound in a context that any prover chooses (Reclaim).
pub fn prover_bound(value: Field) -> Binding {
    Binding { value, set_by: 4 }
}

/// The account address commits to its immutable policy:
/// `immutables_hash = Poseidon2([scheme, policy_hash])`.
pub fn bind_policy(context: &mut PrivateContext, scheme: Field, policy_hash: Field) {
    let instance = get_contract_instance(context.this_address());
    assert_eq(instance.immutables_hash, poseidon2_hash([scheme, policy_hash]), "Wrong account policy");
}

/// Authorisation of this entrypoint's calls, distinct from an authwit interface.
pub fn action_hash(context: &mut PrivateContext, scheme: Field, payload: AppPayload) -> Field {
    poseidon2_hash([
        ENTRYPOINT_DOMAIN,
        scheme,
        context.this_address().to_field(),
        context.chain_id(),
        context.version(),
        payload.hash(),
    ])
}

/// Each entrypoint always consumes its account-siloed transaction nonce.
/// These minimal accounts use external fee payment only.
pub fn execute(context: &mut PrivateContext, payload: AppPayload) {
    context.push_nullifier_unsafe(compute_tx_nullifier(payload.tx_nonce));
    payload.execute_calls(context);
}

/// Canonical lowercase hex of the action, without 0x, for OIDC and SIWE nonces.
pub fn action_hex(action: Field) -> [u8; 64] {
    uc_trust::field_hex(action)
}

/// Poseidon2 of bytes, for adapters that domain-separate session nullifiers.
pub fn bytes_hash<let N: u32>(bytes: [u8; N]) -> Field {
    poseidon2_hash_bytes(bytes)
}
