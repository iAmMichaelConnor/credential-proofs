use crate::{deploy_with_immutables, in_context};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::FromField},
    test::helpers::test_environment::TestEnvironment,
};
use uc_payment_settlement::{
    DOMAIN_ORDER_TERMS, Order, order_reference, Payment, PaymentEvidence, settle, settle_with_bound_order,
};
use uc_trust::{
    ANCHOR_NONE, ANCHOR_PINNED, Binding, SET_BY_MERCHANT, SET_BY_PAYER, SOURCE_CHAIN, SOURCE_PLATFORM, terms_commitment,
    Trust, TrustPolicy,
};

global PLATFORM_KEY: Field = 0x9a7;
global CHAIN_ID: Field = 1;
global ROOT: Field = 0x2007;
global RECEIPT_SCHEME: u32 = 9005;

/// A dummy signed platform receipt with an `N`-byte body (WeChat-like: the
/// merchant sets `attach`). `tag` stands in for the platform signature.
pub struct DummyReceipt<let N: u32> {
    pub platform_key: Field,
    pub body: [u8; N],
    pub transaction_id: Field,
    pub merchant: Field,
    pub currency: Field,
    pub amount: u128,
    pub paid_at: u64,
    pub attach: Field,
    pub tag: Field,
}

impl<let N: u32> DummyReceipt<N> {
    fn signed(self) -> Field {
        poseidon2_hash([
            self.platform_key,
            poseidon2_hash_bytes(self.body),
            self.transaction_id,
            self.merchant,
            self.currency,
            self.amount as Field,
            self.paid_at as Field,
            self.attach,
        ])
    }
}

impl<let N: u32> PaymentEvidence for DummyReceipt<N> {
    let SCHEME: u32 = 9005;

    fn verify(self, _context: &mut PrivateContext) -> Payment {
        assert(self.tag == self.signed(), "Bad receipt signature");
        Payment {
            trust: Trust {
                source: SOURCE_PLATFORM,
                issuer: poseidon2_hash([self.platform_key]),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: 0,
            },
            payment_id: self.transaction_id,
            payee: self.merchant,
            asset: self.currency,
            amount: self.amount,
            paid_at: self.paid_at,
            reference: Binding { value: self.attach, set_by: SET_BY_MERCHANT },
        }
    }
}

/// A dummy chain transfer proven against a pinned root (`root`) at `depth`
/// blocks below it; the payer writes the memo.
pub struct DummyChainTransfer {
    pub root: Field,
    pub depth: u32,
    pub block: Field,
    pub log_index: Field,
    pub to: Field,
    pub token: Field,
    pub value: u128,
    pub block_time: u64,
    pub memo: Field,
}

impl PaymentEvidence for DummyChainTransfer {
    let SCHEME: u32 = 9006;

    fn verify(self, _context: &mut PrivateContext) -> Payment {
        Payment {
            trust: Trust {
                source: SOURCE_CHAIN,
                issuer: CHAIN_ID,
                anchor_kind: ANCHOR_PINNED,
                anchor: self.root,
                finality: self.depth,
                also_authorised: 0,
            },
            payment_id: poseidon2_hash([CHAIN_ID, self.block, self.log_index]),
            payee: self.to,
            asset: self.token,
            amount: self.value,
            paid_at: self.block_time,
            reference: Binding { value: self.memo, set_by: SET_BY_PAYER },
        }
    }
}

fn order(order_id: Field, now: u64) -> Order {
    Order {
        order_id,
        accepted: TrustPolicy {
            source: SOURCE_PLATFORM,
            issuer: poseidon2_hash([PLATFORM_KEY]),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        payee: 10,
        asset: 20,
        amount: 3000,
        beneficiary: AztecAddress::from_field(7),
        not_before: now - 3600,
        not_after: now,
        reference_set_by: SET_BY_MERCHANT,
        external_reference: 0,
        allow_unreferenced: false,
    }
}

fn unreferenced_order(order_id: Field, now: u64) -> Order {
    let mut o = order(order_id, now);
    o.allow_unreferenced = true;
    o
}

fn chain_order(now: u64) -> Order {
    let mut o = order(600, now);
    o.accepted = TrustPolicy {
        source: SOURCE_CHAIN,
        issuer: CHAIN_ID,
        anchor_kind: ANCHOR_PINNED,
        anchor: ROOT,
        min_finality: 64,
        refuse_also: 0,
    };
    o.reference_set_by = SET_BY_PAYER;
    o
}

fn receipt(transaction_id: Field, amount: u128, attach: Field, paid_at: u64) -> DummyReceipt<48> {
    let mut r = DummyReceipt {
        platform_key: PLATFORM_KEY,
        body: [1; 48],
        transaction_id,
        merchant: 10,
        currency: 20,
        amount,
        paid_at,
        attach,
        tag: 0,
    };
    r.tag = r.signed();
    r
}

fn transfer(root: Field, depth: u32, memo: Field, block_time: u64) -> DummyChainTransfer {
    DummyChainTransfer { root, depth, block: 12, log_index: 3, to: 10, token: 20, value: 3000, block_time, memo }
}

/// The reference for `order_id` at the contract the context runs in.
fn reference_here(context: &mut PrivateContext, order_id: Field) -> Field {
    order_reference(
        context.chain_id(),
        context.version(),
        context.this_address(),
        order_id,
    )
}

/// The reference for `order_id` at the contract `at`.
unconstrained fn reference_at(env: TestEnvironment, at: AztecAddress, order_id: Field) -> Field {
    in_context(
        env,
        Option::some(at),
        |context| reference_here(context, order_id),
    )
}

/// Settles with the bound-order variant at the TXE default address. A zero
/// `attach` is replaced by the reference of `reference_for` at that address.
unconstrained fn settle_receipt<let N: u32>(
    env: TestEnvironment,
    order: Order,
    evidence: DummyReceipt<N>,
    reference_for: Field,
) {
    env.private_context(|context| {
        let mut evidence = evidence;
        if evidence.attach == 0 {
            evidence.attach = reference_here(context, reference_for);
            evidence.tag = evidence.signed();
        }
        let payment = settle_with_bound_order(context, order, evidence);
        assert_eq(payment.amount, order.amount);
    });
}

/// As `settle_receipt`, for a chain transfer: a zero memo becomes the order's reference.
unconstrained fn settle_transfer(env: TestEnvironment, order: Order, evidence: DummyChainTransfer) {
    env.private_context(|context| {
        let mut evidence = evidence;
        if evidence.memo == 0 {
            evidence.memo = reference_here(context, order.order_id);
        }
        let _ = settle_with_bound_order(context, order, evidence);
    });
}

/// Deploys a settlement contract for `order`, as an instance of `settle` does.
unconstrained fn deploy_order(env: &mut TestEnvironment, order: Order) -> AztecAddress {
    deploy_with_immutables(
        env,
        terms_commitment(DOMAIN_ORDER_TERMS, RECEIPT_SCHEME as Field, order.hash()),
    )
}

/// Runs the public `settle` at the deployed contract `at`.
unconstrained fn settle_at<let N: u32>(
    env: TestEnvironment,
    at: AztecAddress,
    order: Order,
    evidence: DummyReceipt<N>,
) {
    in_context(
        env,
        Option::some(at),
        |context| {
            let payment = settle(context, order, evidence);
            assert_eq(payment.payment_id, evidence.transaction_id);
        },
    );
}

#[test]
unconstrained fn payment_valid_receipt_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 60), 500);
}

#[test]
unconstrained fn payment_valid_chain_transfer_accepted() {
    // A second evidence type, of another size and trust, through the same core.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_transfer(env, chain_order(now), transfer(ROOT, 64, 0, now - 60));
}

#[test(should_fail_with = "already present")]
unconstrained fn payment_replay_rejected() {
    // Within one contract, the payment nullifier stops a second settlement,
    // even for orders that opt out of the reference check.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(
        env,
        unreferenced_order(500, now),
        receipt(900, 3000, 1, now - 60),
        500,
    );
    settle_receipt(
        env,
        unreferenced_order(501, now),
        receipt(900, 3000, 1, now - 60),
        500,
    );
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn payment_for_another_order_of_this_contract_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 60), 500);
    settle_receipt(env, order(501, now), receipt(900, 3000, 0, now - 60), 500);
}

#[test(should_fail_with = "already present")]
unconstrained fn payment_order_reused_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 60), 500);
    settle_receipt(env, order(500, now), receipt(901, 3000, 0, now - 50), 500);
}

#[test(should_fail_with = "Wrong amount")]
unconstrained fn payment_wrong_amount_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 2999, 0, now - 60), 500);
}

#[test(should_fail_with = "Wrong payee")]
unconstrained fn payment_wrong_payee_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = order(500, now);
    other.payee = 11;
    settle_receipt(env, other, receipt(900, 3000, 0, now - 60), 500);
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn payment_wrong_reference_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 60), 501);
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn payment_bare_order_id_reference_rejected() {
    // The reference binds the contract: the bare order id is not enough.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 500, now - 60), 500);
}

#[test]
unconstrained fn payment_matching_reference_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    env.private_context(|context| {
        let r = receipt(900, 3000, reference_here(context, 500), now - 60);
        let payment = settle_with_bound_order(context, order(500, now), r);
        assert_eq(payment.reference.value, reference_here(context, 500));
    });
}

#[test(should_fail_with = "Payment outside the order window")]
unconstrained fn payment_stale_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 3601), 500);
}

#[test]
unconstrained fn payment_at_not_before_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now - 3600), 500);
}

#[test]
unconstrained fn payment_at_not_after_and_the_anchor_block_accepted() {
    // `not_after` equals the anchor block timestamp here.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_receipt(env, order(500, now), receipt(900, 3000, 0, now), 500);
}

#[test(should_fail_with = "Payment after the anchor block")]
unconstrained fn payment_after_the_anchor_block_rejected() {
    // Inside the order window, but later than the anchor block.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut open = order(500, now);
    open.not_after = now + 3600;
    settle_receipt(env, open, receipt(900, 3000, 0, now + 1), 500);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn payment_wrong_platform_key_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut forged = receipt(900, 3000, 0, now - 60);
    forged.platform_key = 0x666;
    forged.tag = forged.signed();
    settle_receipt(env, order(500, now), forged, 500);
}

#[test(should_fail_with = "Untrusted anchor")]
unconstrained fn payment_untrusted_anchor_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_transfer(env, chain_order(now), transfer(ROOT + 1, 64, 0, now - 60));
}

#[test(should_fail_with = "Insufficient finality")]
unconstrained fn payment_insufficient_finality_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_transfer(env, chain_order(now), transfer(ROOT, 63, 0, now - 60));
}

#[test(should_fail_with = "Untrusted evidence source")]
unconstrained fn payment_chain_evidence_for_a_platform_order_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    settle_transfer(env, order(500, now), transfer(ROOT, 64, 0, now - 60));
}

// The public `settle` at deployed single-order contracts (review B1 and N2).

#[test]
unconstrained fn settle_valid_accepted() {
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let o = order(500, now);
    let a = deploy_order(&mut env, o);
    settle_at(
        env,
        a,
        o,
        receipt(900, 3000, reference_at(env, a, 500), now - 60),
    );
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn settle_wrong_terms_rejected() {
    // An order that the contract does not commit to (another amount).
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let a = deploy_order(&mut env, order(500, now));
    let mut cheaper = order(500, now);
    cheaper.amount = 1;
    settle_at(
        env,
        a,
        cheaper,
        receipt(900, 1, reference_at(env, a, 500), now - 60),
    );
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn settle_opt_out_not_in_the_terms_rejected() {
    // The opt-out is a term: a caller cannot add it to a referenced order.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let a = deploy_order(&mut env, order(500, now));
    settle_at(
        env,
        a,
        unreferenced_order(500, now),
        receipt(900, 3000, 1, now - 60),
    );
}

/// Two single-order contracts with the same order id, payee, asset, amount
/// and window, and different beneficiaries.
unconstrained fn two_orders(
    env: &mut TestEnvironment,
    now: u64,
    a_opts_out: bool,
    b_opts_out: bool,
) -> (Order, AztecAddress, Order, AztecAddress) {
    let mut a = order(500, now);
    a.allow_unreferenced = a_opts_out;
    let mut b = order(500, now);
    b.beneficiary = AztecAddress::from_field(8);
    b.allow_unreferenced = b_opts_out;
    let at_a = deploy_order(env, a);
    let at_b = deploy_order(env, b);
    (a, at_a, b, at_b)
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn settle_one_payment_for_two_contracts_rejected() {
    // Review B1: nullifiers are siloed per contract, so the reference is what
    // stops one receipt from releasing two escrows.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let (a, at_a, b, at_b) = two_orders(&mut env, now, false, false);
    let r = receipt(900, 3000, reference_at(env, at_a, 500), now - 60);
    settle_at(env, at_a, a, r);
    settle_at(env, at_b, b, r);
}

#[test]
unconstrained fn settle_opted_out_contracts_both_accept_one_payment() {
    // The documented risk of `allow_unreferenced`: one payment settles both
    // opted-out orders (cross-contract double settlement).
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let (a, at_a, b, at_b) = two_orders(&mut env, now, true, true);
    let r = receipt(900, 3000, 1, now - 60);
    settle_at(env, at_a, a, r);
    settle_at(env, at_b, b, r);
}

#[test]
unconstrained fn settle_opted_out_contract_accepts_another_orders_payment() {
    // The risk falls on the opted-out order: a payment referenced for B
    // settles B, and it also settles the opted-out A.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let (a, at_a, b, at_b) = two_orders(&mut env, now, true, false);
    let r = receipt(900, 3000, reference_at(env, at_b, 500), now - 60);
    settle_at(env, at_b, b, r);
    settle_at(env, at_a, a, r);
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn settle_referenced_contract_refuses_an_opted_out_orders_payment() {
    // An opted-out A does not weaken a referenced B.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let (a, at_a, b, at_b) = two_orders(&mut env, now, true, false);
    let r = receipt(900, 3000, 1, now - 60);
    settle_at(env, at_a, a, r);
    settle_at(env, at_b, b, r);
}

// Orders that pin an external reference (Peer intent hashes).

/// An order whose payment must carry `external`, not this contract's reference.
fn pinned_order(external: Field, now: u64) -> Order {
    let mut o = order(500, now);
    o.external_reference = external;
    o
}

#[test]
unconstrained fn settle_pinned_external_reference_accepted() {
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let o = pinned_order(0x1e7, now);
    let a = deploy_order(&mut env, o);
    settle_at(env, a, o, receipt(900, 3000, 0x1e7, now - 60));
}

#[test(should_fail_with = "Wrong reference")]
unconstrained fn settle_pinned_order_refuses_its_contract_reference() {
    // The pinned value replaces the contract reference; it is not an alternative.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let o = pinned_order(0x1e7, now);
    let a = deploy_order(&mut env, o);
    settle_at(
        env,
        a,
        o,
        receipt(900, 3000, reference_at(env, a, 500), now - 60),
    );
}

#[test]
unconstrained fn settle_two_contracts_pinning_one_external_reference_both_accept() {
    // The documented risk of `external_reference`: it does not name the
    // contract, so two orders that pin the same value both settle.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let a = pinned_order(0x1e7, now);
    let mut b = pinned_order(0x1e7, now);
    b.beneficiary = AztecAddress::from_field(8);
    let at_a = deploy_order(&mut env, a);
    let at_b = deploy_order(&mut env, b);
    let r = receipt(900, 3000, 0x1e7, now - 60);
    settle_at(env, at_a, a, r);
    settle_at(env, at_b, b, r);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn settle_external_reference_not_in_the_terms_rejected() {
    // The pinned value is a term: a caller cannot swap it.
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let a = deploy_order(&mut env, pinned_order(0x1e7, now));
    settle_at(
        env,
        a,
        pinned_order(0x1e8, now),
        receipt(900, 3000, 0x1e8, now - 60),
    );
}
