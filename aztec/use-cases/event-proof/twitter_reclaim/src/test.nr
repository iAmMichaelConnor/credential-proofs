//! TXE tests of the Reclaim event proof. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `on_event` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! claims from `fixture.nr`. `reclaim_auth::verify_claim` checks the
//! identifier, the parameters hash, the epoch, the claim time and the
//! attestor's EIP-191 signature. Negative cases mutate the valid fixture.
//! No verification key, proof or network is involved.
use crate::fixture::{
    claim, CLAIMED_AT, NOW, OTHER_ATTESTOR_ADDRESS, OTHER_ATTESTOR_X, OTHER_ATTESTOR_Y, resigned_claim, second_claim,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_twitter_reclaim::{claim_context, claim_kind, ReclaimObservation, SCHEME_TWITTER_RECLAIM};
use uc_event_proof::{DOMAIN_EVENT_TERMS, Event, EventTerms, on_event, on_event_with_bound_terms};
use uc_trust::{ALSO_ATTESTOR, ANCHOR_NONE, SOURCE_ATTESTOR, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture attestor key and epoch, the
/// fixture provider and parameters, any context, one hour of freshness.
fn terms() -> EventTerms {
    EventTerms {
        accepted: TrustPolicy {
            source: SOURCE_ATTESTOR,
            issuer: claim().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: claim().kind(),
        match_subject: false,
        subject: 0,
        match_data: false,
        data: 0,
        max_age: 3600,
        scope: 1,
    }
}

/// Deploys the shell with `terms()` and mines a block at `timestamp`, the
/// anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_EVENT_TERMS,
                SCHEME_TWITTER_RECLAIM as Field,
                terms().hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer();
    env.mine_block_at(timestamp);
    (env, at)
}

/// Runs `f` in a private context at the deployed shell.
unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_event_proof::on_event` with the claim.
unconstrained fn observe(env: TestEnvironment, at: AztecAddress, input: ReclaimObservation) -> Event {
    at_shell(env, at, |context| on_event(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn observe_with(env: TestEnvironment, at: AztecAddress, other: EventTerms) -> Event {
    at_shell(
        env,
        at,
        |context| on_event_with_bound_terms(context, other, claim()),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let event = observe(env, at, claim());
    assert_eq(event.trust.source, SOURCE_ATTESTOR);
    assert_eq(event.trust.also_authorised, ALSO_ATTESTOR);
    assert_eq(event.kind, terms().kind);
    assert_eq(event.subject, 0);
    assert_eq(event.data, claim_context(claim().context, claim().context_len));
    assert_eq(event.occurred_at, CLAIMED_AT);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = on_event(context, terms(), claim());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, CLAIMED_AT + 3600);
}

#[test]
unconstrained fn second_claim_accepted() {
    // Another context gives another identifier: another event of the kind.
    let (env, at) = setup(NOW);
    let first = observe(env, at, claim());
    let second = observe(env, at, second_claim());
    assert(first.event_id != second.event_id);
    assert_eq(first.kind, second.kind);
}

// The ECDSA check fails.
#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn wrong_attestor_key_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.attestor_x = OTHER_ATTESTOR_X;
    input.attestor_y = OTHER_ATTESTOR_Y;
    input.attestor_address = OTHER_ATTESTOR_ADDRESS;
    let _ = observe(env, at, input);
}

// The address check fails: the address is not the key's.
#[test(should_fail_with = "address does not match the public key")]
unconstrained fn wrong_attestor_address_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.attestor_address = OTHER_ATTESTOR_ADDRESS;
    let _ = observe(env, at, input);
}

// The signed message names epoch 1, so the ECDSA check fails.
#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn wrong_epoch_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.epoch = 2;
    let _ = observe(env, at, input);
}

// The ECDSA check fails.
#[test(should_fail_with = "Reclaim attestor signature invalid")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.signature[10] ^= 1;
    let _ = observe(env, at, input);
}

// The identifier no longer hashes the context.
#[test(should_fail_with = "Reclaim claim identifier mismatch")]
unconstrained fn changed_context_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.context[2] ^= 1;
    let _ = observe(env, at, input);
}

// The parameters no longer hash to parameters_hash.
#[test(should_fail_with = "Reclaim parameters hash mismatch")]
unconstrained fn changed_parameters_rejected() {
    let (env, at) = setup(NOW);
    let mut input = claim();
    input.parameters[5] ^= 1;
    let _ = observe(env, at, input);
}

#[test]
unconstrained fn other_attestor_key_changes_the_issuer() {
    let mut input = claim();
    input.attestor_x = OTHER_ATTESTOR_X;
    input.attestor_y = OTHER_ATTESTOR_Y;
    assert(input.issuer() != claim().issuer());
    let mut epoch = claim();
    epoch.epoch = 2;
    assert(epoch.issuer() != claim().issuer());
}

#[test(should_fail_with = "already present")]
unconstrained fn resigned_claim_is_a_replay() {
    // The same identifier signed again at another time (and for another
    // owner) is the same event.
    let (env, at) = setup(NOW);
    let _ = observe(env, at, claim());
    assert(resigned_claim().timestamp_s != claim().timestamp_s);
    assert(resigned_claim().owner != claim().owner);
    assert_eq(resigned_claim().identifier, claim().identifier);
    let _ = observe(env, at, resigned_claim());
}

#[test(should_fail_with = "Wrong event kind")]
unconstrained fn wrong_kind_rejected() {
    // Terms for other parameters of the same provider.
    let (env, at) = setup(NOW);
    let mut other = terms();
    let mut parameters_hash = claim().parameters_hash;
    parameters_hash[0] ^= 1;
    other.kind = claim_kind(claim().provider, claim().provider_len, parameters_hash);
    let _ = observe_with(env, at, other);
}

#[test]
unconstrained fn matching_context_accepted() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.match_data = true;
    other.data = claim_context(claim().context, claim().context_len);
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Wrong event data")]
unconstrained fn wrong_context_rejected() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.match_data = true;
    other.data = claim_context(second_claim().context, second_claim().context_len);
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn refused_attestor_rejected() {
    // Terms that refuse attestor authority refuse every Reclaim claim.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.accepted.refuse_also = ALSO_ATTESTOR;
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at) = setup(CLAIMED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = observe_with(env, at, other);
}

// The library rejects a claim time after the anchor block.
#[test(should_fail_with = "Reclaim claim is after the current time")]
unconstrained fn future_claim_rejected() {
    let (env, at) = setup(CLAIMED_AT - 1);
    let _ = observe(env, at, claim());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{CLAIMED_AT, observe_with, setup, terms};

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        let (env, at) = setup(CLAIMED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        let _ = observe_with(env, at, other);
    }
}
