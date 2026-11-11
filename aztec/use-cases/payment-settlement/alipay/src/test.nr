//! TXE tests of the Alipay settlement. Each test deploys the keyless
//! `uc_terms_shell` with this instance's order and runs `settle` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! responses from `fixture.nr`. The RSA2 signature, the response age and the
//! signed trade-query claims are verified by the `alipay` library. Wrong-term cases
//! use separately signed responses; tampering cases mutate a valid one. No
//! verification key, proof or network is involved.
use crate::fixture::{
    late_millisecond, MAX_AGE, NOW, other_amount, OTHER_MODULUS, OTHER_REDC, other_status, other_transaction, payment,
    REFERENCE, TOTAL_FEN,
};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, traits::FromField},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_alipay::{AlipayTradeQuery, ASSET_CNY, payee, SCHEME_ALIPAY};
use uc_payment_settlement::{DOMAIN_ORDER_TERMS, Order, order_reference, Payment, settle, settle_with_bound_order};
use uc_trust::{ANCHOR_NONE, SET_BY_MERCHANT, SOURCE_PLATFORM, terms_commitment, TrustPolicy};

global ORDER_ID: Field = 0x5e771e;

/// The instance's order: 25.00 CNY to the merchant application of the
/// fixture key, paid within a day of `NOW`, the reference set by the merchant
/// in `out_trade_no`.
fn order() -> Order {
    Order {
        order_id: ORDER_ID,
        accepted: TrustPolicy {
            source: SOURCE_PLATFORM,
            issuer: payment().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        payee: payee(payment().modulus),
        asset: ASSET_CNY,
        amount: TOTAL_FEN as u128,
        beneficiary: AztecAddress::from_field(0xbe7),
        not_before: NOW - 86400,
        not_after: NOW + 86400,
        reference_set_by: SET_BY_MERCHANT,
        external_reference: 0,
        allow_unreferenced: false,
    }
}

/// A second contract's order: the same terms for another beneficiary.
fn other_contract_order() -> Order {
    let mut o = order();
    o.beneficiary = AztecAddress::from_field(0xbe8);
    o
}

unconstrained fn deploy(env: &mut TestEnvironment, o: Order) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_ORDER_TERMS,
                SCHEME_ALIPAY as Field,
                o.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

/// Deploys the shell with `order()` (and then `other_contract_order()`), and
/// mines a block at `timestamp`, the anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, order());
    let other = deploy(&mut env, other_contract_order());
    env.mine_block_at(timestamp);
    (env, at, other)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_payment_settlement::settle`.
unconstrained fn settle_at(env: TestEnvironment, at: AztecAddress, o: Order, evidence: AlipayTradeQuery) -> Payment {
    at_shell(env, at, |context| settle(context, o, evidence))
}

/// The rules after term binding, with other order terms at the same address.
unconstrained fn settle_bound(env: TestEnvironment, at: AztecAddress, o: Order, evidence: AlipayTradeQuery) -> Payment {
    at_shell(
        env,
        at,
        |context| settle_with_bound_order(context, o, evidence),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at, _) = setup(NOW + 1);
    let p = settle_at(env, at, order(), payment());
    assert_eq(p.amount, TOTAL_FEN as u128);
    assert_eq(p.paid_at, NOW);
    assert_eq(p.reference.value, REFERENCE);
    assert_eq(p.reference.set_by, SET_BY_MERCHANT);
}

#[test]
unconstrained fn inclusion_limited_by_the_response_age() {
    let (env, at, _) = setup(NOW + 1);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = settle(context, order(), payment());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, NOW + MAX_AGE);
}

#[test]
unconstrained fn valid_within_the_last_millisecond() {
    // A response signed at NOW.999 s: `paid_at` floors to NOW, and an anchor
    // at NOW + MAX_AGE is 299.001 s later, within the maximum age.
    let (env, at, _) = setup(NOW + MAX_AGE);
    let p = settle_at(env, at, order(), late_millisecond());
    assert_eq(p.paid_at, NOW);
}

#[test(should_fail_with = "stale response")]
unconstrained fn stale_by_one_second_after_a_late_millisecond_rejected() {
    // NOW + MAX_AGE + 1 is 300.001 s after NOW.999 s.
    let (env, at, _) = setup(NOW + MAX_AGE + 1);
    let _ = settle_at(env, at, order(), late_millisecond());
}

#[test(should_fail_with = "future response timestamp")]
unconstrained fn late_millisecond_after_the_anchor_second_rejected() {
    // An anchor at NOW (NOW.000 s) is before a response at NOW.999 s.
    let (env, at, _) = setup(NOW);
    let _ = settle_at(env, at, order(), late_millisecond());
}

#[test]
unconstrained fn valid_at_the_response_time() {
    // Age 0: the anchor block has the response's timestamp.
    let (env, at, _) = setup(NOW);
    let _ = settle_at(env, at, order(), payment());
}

#[test(should_fail_with = "stale response")]
unconstrained fn stale_rejected() {
    let (env, at, _) = setup(NOW + MAX_AGE + 1);
    let _ = settle_at(env, at, order(), payment());
}

#[test(should_fail_with = "future response timestamp")]
unconstrained fn response_after_the_anchor_block_rejected() {
    let (env, at, _) = setup(NOW - 1);
    let _ = settle_at(env, at, order(), payment());
}

#[test(should_fail_with = "Payment outside the order window")]
unconstrained fn payment_outside_the_order_window_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let mut late = order();
    late.not_after = NOW - 1;
    let _ = settle_bound(env, at, late, payment());
}

#[test(should_fail_with = "already present")]
unconstrained fn order_reused_rejected() {
    // A second, genuine payment with the same reference: the order nullifier
    // stops it.
    let (env, at, _) = setup(NOW + 1);
    let _ = settle_at(env, at, order(), payment());
    let _ = settle_at(env, at, order(), other_transaction());
}

#[test(should_fail_with = "Wrong amount")]
unconstrained fn wrong_amount_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let _ = settle_at(env, at, order(), other_amount());
}

#[test(should_fail_with = "Wrong payee")]
unconstrained fn wrong_payee_rejected() {
    // An order for another merchant application's key, with this key's trust:
    // the payee is the key itself.
    let (env, at, _) = setup(NOW + 1);
    let mut o = order();
    o.payee = payee(OTHER_MODULUS);
    let _ = settle_bound(env, at, o, payment());
}

#[test(should_fail_with = "wrong claim value")]
unconstrained fn unpaid_trade_rejected() {
    // A genuine response whose trade_status is WAIT_BUYER_PAY.
    let (env, at, _) = setup(NOW + 1);
    let _ = settle_at(env, at, order(), other_status());
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn wrong_reference_rejected() {
    // Review B1: the payment for this contract's order does not settle the
    // same order at another contract.
    let (env, _, other) = setup(NOW + 1);
    let _ = settle_at(env, other, other_contract_order(), payment());
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn wrong_order_id_rejected() {
    // Another order id at this contract has another reference.
    let (env, at, _) = setup(NOW + 1);
    let mut o = order();
    o.order_id = ORDER_ID + 1;
    let _ = settle_bound(env, at, o, payment());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_maximum_age_rejected() {
    // The maximum age is part of the pinned issuer.
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.max_age = MAX_AGE - 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "Bad maximum age")]
unconstrained fn maximum_age_above_the_cap_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.max_age = 301;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // Another well-formed key: the RSA check fails. The
    // key also changes the issuer pin.
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.modulus = OTHER_MODULUS;
    input.redc = OTHER_REDC;
    assert(input.issuer() != payment().issuer());
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.signature[3] += 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn tampered_body_rejected() {
    // "25.00" becomes "26.00" in the signed body; the claims still match the
    // altered body, so only the signature fails.
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    let mut storage = input.body.storage();
    let mut found = false;
    for i in 0..507 {
        if !found
            & (storage[i] == 0x32)
            & (storage[i + 1] == 0x35)
            & (storage[i + 2] == 0x2e)
            & (storage[i + 3] == 0x30)
            & (storage[i + 4] == 0x30) {
            storage[i + 1] = 0x36;
            found = true;
        }
    }
    assert(found);
    input.body = BoundedVec::from_parts(storage, input.body.len());
    input.total_fen = 2600;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "wrong claim value")]
unconstrained fn claimed_amount_not_in_the_body_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.total_fen = TOTAL_FEN + 1;
    let _ = settle_at(env, at, order(), input);
}

#[test(should_fail_with = "wrong claim value")]
unconstrained fn claimed_out_trade_no_not_in_the_body_rejected() {
    let (env, at, _) = setup(NOW + 1);
    let mut input = payment();
    input.out_trade_no[0] = if input.out_trade_no[0] == 0x30 {
        0x31
    } else {
        0x30
    };
    let _ = settle_at(env, at, order(), input);
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{at_shell, MAX_AGE, NOW, order, ORDER_ID, order_reference, payment, REFERENCE, settle_at, setup};

    #[test]
    unconstrained fn fixture_reference_is_the_order_reference() {
        let (env, at, _) = setup(NOW);
        let reference = at_shell(
            env,
            at,
            |context| order_reference(
                context.chain_id(),
                context.version(),
                context.this_address(),
                ORDER_ID,
            ),
        );
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/platform_payment.mjs --instance payment-settlement/alipay --reference
        // <reference>
        assert(
            reference == REFERENCE,
            f"Fixture out_trade_no is not the order reference {reference}; regenerate the fixture",
        );
    }

    #[test]
    unconstrained fn valid_at_the_maximum_age() {
        let (env, at, _) = setup(NOW + MAX_AGE);
        let _ = settle_at(env, at, order(), payment());
    }
}
