//! Payment-settlement core (use case U5): "a payment matching this order
//! happened; the order's fixed effect happens once". The beneficiary is fixed
//! in the order, so a copy of the payment evidence cannot redirect the
//! effect. No holder key is involved.
//!
//! Nullifiers are siloed per contract, and `settle` binds one order to each
//! contract. The payment nullifier therefore cannot stop a second contract
//! from accepting the same payment. The order reference does: by default the
//! payment must carry `order_reference` for this contract and order, so it
//! can settle no other order.
use aztec::{
    context::PrivateContext,
    protocol::{
        address::AztecAddress,
        hash::{poseidon2_hash, poseidon2_hash_bytes},
        traits::{Deserialize, Serialize, ToField},
    },
};
use std::meta::derive;
use uc_trust::{assert_trust_accepted, Binding, SET_BY_NONE, Trust, TrustPolicy};

mod tests;

pub global DOMAIN_PAYMENT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PAYMENT_V1".as_bytes()) };
pub global DOMAIN_ORDER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PAYMENT_ORDER_V1".as_bytes()) };
pub global DOMAIN_ORDER_TERMS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PAYMENT_TERMS_V1".as_bytes()) };
pub global DOMAIN_ORDER_REFERENCE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PAYMENT_REFERENCE_V1".as_bytes()) };

/// What an adapter proves about one payment.
#[derive(Eq, Serialize, Deserialize)]
pub struct Payment {
    pub trust: Trust,
    /// Platform transaction id or Peer payment id. Nonzero.
    pub payment_id: Field,
    /// Merchant id, payee id or recipient address hash.
    pub payee: Field,
    /// Currency or token contract hash.
    pub asset: Field,
    pub amount: u128,
    pub paid_at: u64,
    /// The order reference the payment carries, and who set it.
    pub reference: Binding,
}

/// The order, committed in the contract's `immutables_hash`.
#[derive(Eq, Serialize, Deserialize)]
pub struct Order {
    pub order_id: Field,
    pub accepted: TrustPolicy,
    pub payee: Field,
    pub asset: Field,
    pub amount: u128,
    /// Receives the fixed effect (release or mint).
    pub beneficiary: AztecAddress,
    /// Inclusive window for `paid_at`.
    pub not_before: u64,
    pub not_after: u64,
    /// Who must have set the payment's reference (`SET_BY_*`). The reference
    /// must equal `order_reference` for this contract and `order_id`.
    pub reference_set_by: u8,
    /// 0, or a reference fixed outside this contract that the payment must
    /// carry instead of `order_reference` (a Peer V4 intent hash, which is
    /// unique per Peer intent). It does not name this contract: every
    /// contract whose order pins the same value accepts the same payment
    /// (cross-contract double settlement). Pin each value in one order only
    ///.
    pub external_reference: Field,
    /// Opt-out: accept the payment without checking its reference. Risk:
    /// cross-contract double settlement. Nullifiers are siloed per contract,
    /// so one payment then settles every opted-out order, at any contract,
    /// whose payee, asset, amount, window and trust it matches, including a
    /// payment made for another order. Use it only when no other order can
    /// match the same payment, or with a shared payment-nullifier registry
    ///.
    pub allow_unreferenced: bool,
}

impl Order {
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// Implemented by an adapter's input struct for each payment source.
pub trait PaymentEvidence {
    let SCHEME: u32;
    fn verify(self, context: &mut PrivateContext) -> Payment;
}

/// One settlement per payment per scheme, domain-separated.
/// The adapter's `payment_id` may keep an upstream format (for example
/// Peer's keccak(method || payment_id)). Aztec silos it by contract address,
/// so it blocks a second settlement only within one contract. It includes
/// the scheme, so one transfer proven through two adapters of one contract
/// gives two nullifiers. Rule: a contract accepts
/// one scheme. `settle` enforces it, because the terms commitment includes
/// `E::SCHEME`; a contract that calls `settle_with_bound_order` must use one
/// evidence type.
pub fn payment_nullifier(scheme: Field, payment_id: Field) -> Field {
    uc_trust::scoped_nullifier(DOMAIN_PAYMENT, scheme, payment_id)
}

/// One settlement per order.
pub fn order_nullifier(order_id: Field) -> Field {
    uc_trust::scoped_nullifier(DOMAIN_ORDER, 0, order_id)
}

/// The reference that a payment must carry to settle `order_id` at the
/// contract `this_address` on this chain. It differs for every contract, so a
/// payment made for one order cannot settle an order of another contract.
pub fn order_reference(chain_id: Field, version: Field, this_address: AztecAddress, order_id: Field) -> Field {
    poseidon2_hash(
        [DOMAIN_ORDER_REFERENCE, chain_id, version, this_address.to_field(), order_id],
    )
}

/// The reference from its text form: exactly 64 lowercase hex digits of the
/// canonical 32-byte big-endian value (`uc_trust::field_hex`). This is the
/// form that a merchant field (WeChat `attach`, Alipay `out_trade_no`)
/// carries. Rejects any other spelling, including a value
/// at or above the field modulus, so one reference has one text.
pub fn reference_from_hex(text: [u8; 64]) -> Field {
    let mut value: Field = 0;
    for i in 0..64 {
        let c = text[i];
        let digit = if (c >= 48) & (c <= 57) {
            c - 48
        } else {
            assert((c >= 97) & (c <= 102), "Reference is not lowercase hex");
            c - 87
        };
        value = value * 16 + digit as Field;
    }
    assert(uc_trust::field_hex(value) == text, "Reference is not canonical");
    value
}

/// Settlement rules that need no context: trust accepted, the payment
/// matches the order's payee, asset, amount and window, and carries
/// `reference` (the `order_reference` of this contract and order), or the
/// order's nonzero `external_reference`, set by `order.reference_set_by`,
/// unless the order opts out with `allow_unreferenced`. Not public: an
/// instance that passed another `reference` would bypass the contract
/// binding. Instances call `settle` or `settle_with_bound_order`.
pub(crate) fn assert_payment_matches(order: Order, payment: Payment, reference: Field) {
    assert_trust_accepted(payment.trust, order.accepted);
    assert(payment.payee == order.payee, "Wrong payee");
    assert(payment.asset == order.asset, "Wrong asset");
    assert(payment.amount == order.amount, "Wrong amount");
    assert(
        (order.not_before <= payment.paid_at) & (payment.paid_at <= order.not_after),
        "Payment outside the order window",
    );
    if order.allow_unreferenced {
        assert(order.external_reference == 0, "An unreferenced order pins no reference");
    } else {
        let expected = if order.external_reference != 0 {
            order.external_reference
        } else {
            reference
        };
        assert(payment.reference.set_by != SET_BY_NONE, "Payment carries no reference");
        assert(payment.reference.set_by == order.reference_set_by, "Reference set by another party");
        assert(payment.reference.value == expected, "Wrong reference");
    }
    assert(payment.payment_id != 0, "Missing payment id");
}

/// Settles the order once: binds the order to the contract, then applies
/// `settle_with_bound_order`. The instance applies the fixed effect to
/// `order.beneficiary`.
pub fn settle<E>(context: &mut PrivateContext, order: Order, evidence: E) -> Payment
where
    E: PaymentEvidence,
{
    uc_trust::bind_terms(
        context,
        DOMAIN_ORDER_TERMS,
        E::SCHEME as Field,
        order.hash(),
    );
    settle_with_bound_order(context, order, evidence)
}

/// As `settle`, for a caller that has already authenticated `order` (for
/// example an order held in contract storage). Several orders of one
/// contract need distinct `order_id` values, and the contract must accept
/// one evidence type only (see `payment_nullifier`).
pub fn settle_with_bound_order<E>(context: &mut PrivateContext, order: Order, evidence: E) -> Payment
where
    E: PaymentEvidence,
{
    let payment = evidence.verify(context);
    let reference = order_reference(
        context.chain_id(),
        context.version(),
        context.this_address(),
        order.order_id,
    );
    assert_payment_matches(order, payment, reference);
    assert(payment.paid_at <= context.get_anchor_block_header().timestamp(), "Payment after the anchor block");
    context.push_nullifier_unsafe(payment_nullifier(E::SCHEME as Field, payment.payment_id));
    context.push_nullifier_unsafe(order_nullifier(order.order_id));
    payment
}
