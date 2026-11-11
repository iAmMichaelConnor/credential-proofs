> **Experimental software. Unaudited. May contain bugs.**

# Payment settlement (U5)

Statement: "a payment matching this order happened; the order's fixed
effect happens once". The order names the beneficiary, so a copy of the
payment evidence cannot redirect the effect. No separately enrolled holder
key is involved.

Core crate: [`uc_payment_settlement`](common/src/lib.nr) (`PaymentEvidence`,
`Payment`, `Order { order_id, accepted, payee, asset, amount, beneficiary,
not_before, not_after, reference_set_by, external_reference,
allow_unreferenced }`, `settle`, `order_reference`, `reference_from_hex`).
`assert_payment_matches` is not public: an instance that passed another
reference would bypass the contract binding. Instances call `settle`, or
`settle_with_bound_order` after authenticating the order. Every instance
delivers a `Settled { order_id, payment_id, amount }` event to
`order.beneficiary`; none releases or mints tokens.

## Rules

1. Trust accepted: the platform key or attestor (and, for evidence that
   carries an anchor, its kind, pinned value and minimum finality).
2. Payee, asset and amount equal the order's.
3. `not_before <= paid_at <= not_after`, and the payment is not after the
   anchor block.
4. The payment carries the reference `Poseidon2(MIKE_UC_PAYMENT_REFERENCE_V1,
   chain_id, version, this_address, order_id)` (as 64 lowercase hex digits
   in a text field), set by `reference_set_by`. It names this contract, so a
   payment for one order settles no order of another contract. An order with
   a nonzero `external_reference` (a Peer intent hash) requires that value
   instead; only `allow_unreferenced` skips the check.
5. Nullifiers: `Poseidon2(MIKE_UC_PAYMENT_V1, SCHEME, payment_id)` (one
   settlement per payment per contract) and
   `Poseidon2(MIKE_UC_PAYMENT_ORDER_V1, 0, order_id)` (one per order). With
   one order per contract (`settle`) the payment nullifier adds nothing; it
   matters for contracts that hold several orders
   (`settle_with_bound_order`). `payment_id` can keep Peer's
   `keccak(method || payment_id)`.

## Residual risks

- `allow_unreferenced`: nullifiers are siloed per contract, so a payment
  settles every opted-out order, at any contract, whose payee, asset,
  amount, window and trust it matches, including a payment made with its
  reference for another order. Example: seller M deploys escrows A and B,
  both for 100 units to M on platform P, both opted out; one payment
  releases both. Use the opt-out only when no other order can match the
  payment.
- `external_reference` does not name the contract: every order that pins the
  same value accepts the same payment. Pin each value in one order only.
- The payment nullifier includes `SCHEME`, so one transfer reaching a
  contract through two adapters gets two nullifiers. A contract accepts one
  scheme: `settle` enforces it through the terms commitment; a
  `settle_with_bound_order` contract must accept one evidence type.
- A merchant-set reference shows what the merchant recorded, not what the
  payer approved. The platform key or attestor is trusted to sign only real
  payments.

## Tests

`common/src/tests.nr` covers the context-free rules, both window bounds, the
opt-out, the external reference, the per-contract references, the reference
text form and the nullifier separation. `../testing/core_tests/src/payment.nr`
(TXE) uses two dummy evidence types of different sizes and trust (a signed
platform receipt and a transfer under a pinned anchor): valid settlements, replay
for a second order and within one contract, order reuse, wrong amount, payee
and reference, a bare order id as reference, stale and future payments,
both window bounds, a wrong key, an untrusted anchor, insufficient finality
and anchored evidence for a platform order. At deployed single-order shells it
covers `settle` with valid and wrong terms, one receipt against two
referenced contracts (rejected at the second), and the documented risks: two
opted-out contracts that both accept one receipt, and two contracts that pin
one external reference. With a contract-bound reference, each instance test
rejects the same payment at a second contract; peer_v4's shows that a second
contract that pins the same intent accepts it.

## Instances

<!-- use-case-instances:start -->
Each instance is a contract in `<scheme>/src/main.nr`, entrypoint `settle(order, evidence)`, package `<scheme>_payment_settlement`, tested by `scripts/test-use-cases.sh payment-settlement/<scheme>`. Its `src/test.nr` has the tests `valid`, `wrong_amount_rejected`, `wrong_payee_rejected`, `wrong_reference_rejected`, `order_reused_rejected`; [use-cases.json](../use-cases.json) records each exception and its reason. The category is the evidence category of [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).

| Instance | Category | Contract | Adapter | Residual risk and notes |
| --- | --- | --- | --- | --- |
| [alipay](alipay/src/main.nr) | 5 | `AlipaySettlement` | [`uc_adapter_alipay`](../adapters/alipay/src/lib.nr) | Does not establish merchant or app identity: `payee` is a hash of the response-signing key, which can be shared across app ids, so a response from another merchant context with matching amount and `out_trade_no` settles. Not sufficient for merchant-bound settlement. Reference: `out_trade_no`, set by the merchant. `paid_at` is the response time. Responses with nested values (for example `fund_bill_list`) fail closed; `TRADE_FINISHED` and service-provider (ISV) mode are unsupported. |
| [peer_v4](peer_v4/src/main.nr) | 5 | `PeerV4Settlement` | [`uc_adapter_peer_v4`](../adapters/peer_v4/src/lib.nr) | Reference: the Peer intent hash (`external_reference`), which does not name this contract: two orders that pin the same intent both settle one payment. Pin each intent in one order only. The same attestation also releases the intent's escrow on Base. Fiat reversal and the intent's Base state are not checked. A multisig witness set needs a threshold-aware adapter. |
| [wechatpay](wechatpay/src/main.nr) | 5 | `WechatpaySettlement` | [`uc_adapter_wechatpay`](../adapters/wechatpay/src/lib.nr) | Reference: `attach`, set by the merchant: it shows what the merchant recorded, not what the payer approved. `paid_at` is the response time, not `success_time`. A coupon payment settles at `amount.total`, which can exceed what the payer paid. Bodies over 1024 bytes fail closed. |
<!-- use-case-instances:end -->
