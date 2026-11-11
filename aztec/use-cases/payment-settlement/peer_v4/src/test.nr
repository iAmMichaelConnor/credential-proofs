//! TXE tests of the Peer V4 settlement. Each test deploys the keyless
//! `uc_terms_shell` with this instance's order and runs `settle` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! attestations from `fixture.nr`. The attestor's EIP-712 signature, the
//! data hash and ABI layout and the payment age are verified by the
//! `peer_v4_auth` library. Wrong-term cases use separately signed
//! attestations; tampering cases mutate a valid one. No verification key,
//! proof or network is involved.
use crate::fixture::{
    CURRENCY, early_payment, FIAT_AMOUNT, INTENT_HASH, MAX_AGE_MS, METHOD, NOW, other_amount, other_intent, other_payee,
    other_payment, PAID_AT, PAYEE_ID, payment,
};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::FromField},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_peer_v4::{asset, payee, PeerV4Payment, SCHEME_PEER_V4};
use uc_payment_settlement::{DOMAIN_ORDER_TERMS, Order, Payment, settle, settle_with_bound_order};
use uc_trust::{ANCHOR_NONE, SET_BY_PAYER, SOURCE_ATTESTOR, terms_commitment, TrustPolicy};

global ORDER_ID: Field = 0x9ee4;

/// The instance's order: the fixture fiat amount, currency and payee, paid
/// within a day before `NOW`, for the pinned Peer intent.
fn order() -> Order {
    Order {
        order_id: ORDER_ID,
        accepted: TrustPolicy {
            source: SOURCE_ATTESTOR,
            issuer: payment().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        payee: payee(METHOD, PAYEE_ID),
        asset: asset(CURRENCY),
        amount: FIAT_AMOUNT,
        beneficiary: AztecAddress::from_field(0xbe7),
        not_before: NOW - 86400,
        not_after: NOW,
        reference_set_by: SET_BY_PAYER,
        external_reference: INTENT_HASH,
        allow_unreferenced: false,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, o: Order) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_ORDER_TERMS,
                SCHEME_PEER_V4 as Field,
                o.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

/// Deploys the shell with `o` and mines a block at `timestamp`, the anchor
/// of the next private context.
unconstrained fn setup_with(o: Order, timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, o);
    env.mine_block_at(timestamp);
    (env, at)
}

unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    setup_with(order(), timestamp)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_payment_settlement::settle`.
unconstrained fn settle_at(env: TestEnvironment, at: AztecAddress, o: Order, evidence: PeerV4Payment) -> Payment {
    at_shell(env, at, |context| settle(context, o, evidence))
}

/// The rules after term binding, with other order terms at the same address.
unconstrained fn settle_bound(env: TestEnvironment, at: AztecAddress, o: Order, evidence: PeerV4Payment) -> Payment {
    at_shell(
        env,
        at,
        |context| settle_with_bound_order(context, o, evidence),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let p = settle_at(env, at, order(), payment());
    assert_eq(p.amount, FIAT_AMOUNT);
    assert_eq(p.paid_at, PAID_AT);
    assert_eq(p.reference.value, INTENT_HASH);
    assert_eq(p.reference.set_by, SET_BY_PAYER);
}

#[test]
unconstrained fn inclusion_limited_by_the_payment_age() {
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = settle(context, order(), payment());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, PAID_AT + MAX_AGE_MS / 1000);
}

#[test(should_fail_with = "peer payment is older than policy allows")]
unconstrained fn stale_rejected() {
    let mut o = order();
    o.not_after = NOW + 86400;
    let (env, at) = setup_with(o, PAID_AT + MAX_AGE_MS / 1000 + 1);
    let _ = settle_at(env, at, o, payment());
}

#[test(should_fail_with = "peer payment is after the current time")]
unconstrained fn payment_after_the_anchor_block_rejected() {
    // The library's payment_time <= now check.
    let (env, at) = setup(PAID_AT - 1);
    let _ = settle_at(env, at, order(), payment());
}

#[test(should_fail_with = "Payment outside the order window")]
unconstrained fn payment_outside_the_order_window_rejected() {
    let (env, at) = setup(NOW);
    let mut early = order();
    early.not_after = PAID_AT - 1;
    let _ = settle_bound(env, at, early, payment());
}

#[test(should_fail_with = "already present")]
unconstrained fn order_reused_rejected() {
    // A second, genuine payment for the same intent: the order nullifier stops it.
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), payment());
    let _ = settle_at(env, at, order(), other_payment());
}

#[test(should_fail_with = "already present")]
unconstrained fn payment_replayed_for_another_order_of_this_contract_rejected() {
    // Within one contract the payment nullifier stops a second order (the
    // bound-order variant, with a second order id and the same intent).
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), payment());
    let mut second = order();
    second.order_id = ORDER_ID + 1;
    let _ = settle_bound(env, at, second, payment());
}

#[test(should_fail_with = "Payment before the Peer intent")]
unconstrained fn payment_before_the_intent_rejected() {
    // A genuine attestation whose payment is older than the intent's signal
    // time minus its buffer (Peer's own timing rule).
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), early_payment());
}

#[test(should_fail_with = "Wrong amount")]
unconstrained fn wrong_amount_rejected() {
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), other_amount());
}

#[test(should_fail_with = "Wrong payee")]
unconstrained fn wrong_payee_rejected() {
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), other_payee());
}

#[test(should_fail_with = "Wrong asset")]
unconstrained fn wrong_currency_rejected() {
    let (env, at) = setup(NOW);
    let mut o = order();
    o.asset = asset(METHOD);
    let _ = settle_bound(env, at, o, payment());
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn wrong_reference_rejected() {
    // A genuine payment for another Peer intent.
    let (env, at) = setup(NOW);
    let _ = settle_at(env, at, order(), other_intent());
}

#[test]
unconstrained fn second_contract_pinning_the_intent_also_accepts() {
    // The documented risk of `external_reference`: it does not name the
    // contract, so a second order that pins the same intent settles too.
    let mut env = TestEnvironment::new();
    let a = deploy(&mut env, order());
    let mut other = order();
    other.beneficiary = AztecAddress::from_field(0xbe8);
    let b = deploy(&mut env, other);
    env.mine_block_at(NOW);
    let _ = settle_at(env, a, order(), payment());
    let _ = settle_at(env, b, other, payment());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_maximum_age_rejected() {
    // The maximum age is part of the pinned issuer.
    let (env, at) = setup(NOW);
    let mut input = payment();
    input.max_payment_age_ms = MAX_AGE_MS - 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "peer attestor address does not match its key")]
unconstrained fn wrong_attestor_key_rejected() {
    // Another public key with the pinned address: the library's address
    // derivation check fails first, before ECDSA.
    let (env, at) = setup(NOW);
    let mut input = payment();
    input.attestor_y[31] = input.attestor_y[31] ^ 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "peer attestor signature invalid")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = payment();
    input.signature[10] = input.signature[10] ^ 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "peer data hash mismatch")]
unconstrained fn tampered_data_rejected() {
    // A higher fiat amount in the data: keccak256(data) no longer matches.
    let (env, at) = setup(NOW);
    let mut input = payment();
    input.data[95] = input.data[95] + 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "Bad maximum age")]
unconstrained fn maximum_age_above_the_cap_rejected() {
    let (env, at) = setup(NOW);
    let mut input = payment();
    input.max_payment_age_ms = 86_400_001;
    let _ = settle_at(env, at, order(), input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{MAX_AGE_MS, NOW, order, PAID_AT, payment, settle_at, setup_with};

    #[test]
    unconstrained fn valid_at_the_maximum_age() {
        let mut o = order();
        o.not_after = NOW + 86400;
        let (env, at) = setup_with(o, PAID_AT + MAX_AGE_MS / 1000);
        let _ = settle_at(env, at, o, payment());
    }
}
