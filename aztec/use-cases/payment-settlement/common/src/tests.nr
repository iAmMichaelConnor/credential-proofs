// Plain unit tests of the context-free settlement rules; TXE tests are in
// aztec/use-cases/testing/core_tests.
use crate::{
    assert_payment_matches, Order, order_nullifier, order_reference, Payment, payment_nullifier, reference_from_hex,
};
use aztec::{
    authwit::account::compute_tx_nullifier,
    protocol::{address::AztecAddress, hash::poseidon2_hash_bytes, traits::FromField},
};
use uc_trust::{ANCHOR_NONE, Binding, SET_BY_MERCHANT, SET_BY_NONE, SET_BY_PAYER, SOURCE_PLATFORM, Trust, TrustPolicy};

/// The reference that `order()` expects in these context-free tests.
global REFERENCE: Field = 0x5ef;

fn order(allow_unreferenced: bool) -> Order {
    Order {
        order_id: 500,
        accepted: TrustPolicy {
            source: SOURCE_PLATFORM,
            issuer: 5,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        payee: 10,
        asset: 20,
        amount: 3000,
        beneficiary: AztecAddress::from_field(7),
        not_before: 100,
        not_after: 200,
        reference_set_by: SET_BY_MERCHANT,
        external_reference: 0,
        allow_unreferenced,
    }
}

fn payment() -> Payment {
    Payment {
        trust: Trust {
            source: SOURCE_PLATFORM,
            issuer: 5,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            finality: 0,
            also_authorised: 0,
        },
        payment_id: 900,
        payee: 10,
        asset: 20,
        amount: 3000,
        paid_at: 150,
        reference: Binding { value: REFERENCE, set_by: SET_BY_MERCHANT },
    }
}

#[test]
fn matching_payment_accepted() {
    assert_payment_matches(order(false), payment(), REFERENCE);
}

#[test]
fn opted_out_order_ignores_the_reference() {
    let mut p = payment();
    p.reference = Binding { value: 0, set_by: SET_BY_NONE };
    assert_payment_matches(order(true), p, REFERENCE);
    p.reference = Binding { value: REFERENCE + 1, set_by: SET_BY_PAYER };
    assert_payment_matches(order(true), p, REFERENCE);
}

#[test]
fn external_reference_replaces_the_contract_reference() {
    // A Peer order pins the intent hash.
    let mut o = order(false);
    o.external_reference = 0x1e7;
    let mut p = payment();
    p.reference.value = 0x1e7;
    assert_payment_matches(o, p, REFERENCE);
}

#[test(should_fail_with = "Wrong reference")]
fn contract_reference_rejected_when_an_external_reference_is_pinned() {
    let mut o = order(false);
    o.external_reference = 0x1e7;
    assert_payment_matches(o, payment(), REFERENCE);
}

#[test(should_fail_with = "Wrong reference")]
fn other_external_reference_rejected() {
    let mut o = order(false);
    o.external_reference = 0x1e7;
    let mut p = payment();
    p.reference.value = 0x1e8;
    assert_payment_matches(o, p, REFERENCE);
}

#[test(should_fail_with = "An unreferenced order pins no reference")]
fn opted_out_order_with_an_external_reference_rejected() {
    let mut o = order(true);
    o.external_reference = 0x1e7;
    assert_payment_matches(o, payment(), REFERENCE);
}

#[test]
fn payments_at_the_window_bounds_accepted() {
    let mut p = payment();
    p.paid_at = 100;
    assert_payment_matches(order(false), p, REFERENCE);
    p.paid_at = 200;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test]
fn references_differ_per_contract_and_order() {
    let a = AztecAddress::from_field(0xa);
    let b = AztecAddress::from_field(0xb);
    assert(order_reference(1, 1, a, 500) != order_reference(1, 1, b, 500));
    assert(order_reference(1, 1, a, 500) != order_reference(1, 1, a, 501));
    assert(order_reference(1, 1, a, 500) != order_reference(2, 1, a, 500));
    assert(order_reference(1, 1, a, 500) != order_reference(1, 2, a, 500));
    assert(order_reference(1, 1, a, 500) != 500);
}

#[test(should_fail_with = "Wrong amount")]
fn wrong_amount_rejected() {
    let mut p = payment();
    p.amount = 2999;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Wrong payee")]
fn wrong_payee_rejected() {
    let mut p = payment();
    p.payee = 11;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Wrong asset")]
fn wrong_asset_rejected() {
    let mut p = payment();
    p.asset = 21;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Wrong reference")]
fn wrong_reference_rejected() {
    let mut p = payment();
    p.reference.value = 501;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Reference set by another party")]
fn reference_from_the_wrong_party_rejected() {
    let mut p = payment();
    p.reference.set_by = SET_BY_PAYER;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Payment carries no reference")]
fn missing_reference_rejected() {
    let mut p = payment();
    p.reference = Binding { value: 500, set_by: SET_BY_NONE };
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Payment outside the order window")]
fn stale_payment_rejected() {
    let mut p = payment();
    p.paid_at = 99;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Payment outside the order window")]
fn late_payment_rejected() {
    let mut p = payment();
    p.paid_at = 201;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Untrusted issuer")]
fn wrong_platform_key_rejected() {
    let mut p = payment();
    p.trust.issuer = 6;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test(should_fail_with = "Missing payment id")]
fn missing_payment_id_rejected() {
    let mut p = payment();
    p.payment_id = 0;
    assert_payment_matches(order(false), p, REFERENCE);
}

#[test]
fn nullifiers_are_domain_separated() {
    // The payment nullifier is tagged, per scheme, and
    // independent of the order it settles.
    let id = poseidon2_hash_bytes([7; 32]);
    assert(payment_nullifier(1, id) != payment_nullifier(2, id));
    assert(payment_nullifier(1, id) != id);
    assert(payment_nullifier(1, id) != order_nullifier(id));
    assert(payment_nullifier(1, id) != compute_tx_nullifier(id));
    assert(order_nullifier(500) != order_nullifier(501));
}

#[test]
fn reference_text_round_trips() {
    let reference = order_reference(1, 1, AztecAddress::from_field(0xa), 500);
    assert_eq(reference_from_hex(uc_trust::field_hex(reference)), reference);
    assert_eq(reference_from_hex(uc_trust::field_hex(0)), 0);
    assert_eq(reference_from_hex(uc_trust::field_hex(-1)), -1);
}

#[test(should_fail_with = "Reference is not lowercase hex")]
fn uppercase_reference_text_rejected() {
    let mut text = uc_trust::field_hex(0xabc);
    text[63] = 0x43; // 'C'
    let _ = reference_from_hex(text);
}

#[test(should_fail_with = "Reference is not canonical")]
fn reference_text_at_the_modulus_rejected() {
    // p itself: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.
    let text = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001".as_bytes();
    let _ = reference_from_hex(text);
}
