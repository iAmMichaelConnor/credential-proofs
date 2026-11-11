//! Alipay adapter: an Alipay-signed v3 trade-query response
//! (`alipay.trade.query`) as payment evidence
//! (`uc_payment_settlement::PaymentEvidence`).
//!
//! `alipay::verify_v3_response` checks the RSA2 signature over
//! `timestamp LF nonce LF body LF` (millisecond timestamp) and the response
//! age; `alipay::assert_trade_query_claims` binds `trade_no`,
//! `out_trade_no`, `trade_status == "TRADE_SUCCESS"` and `total_amount` to
//! the same signed flat body.
//!
//! The merchant sets `out_trade_no` when it creates the trade. Settlement
//! requires it to be the order reference in text form (64 lowercase hex
//! digits, `uc_payment_settlement::reference_from_hex`), reported as
//! `SET_BY_MERCHANT`. The selected claims bind no seller, and the v3 signature
//! does not cover the app id. The current `payee` is a pinned key identifier;
//! it does not establish merchant/application identity. A per-app key guarantee
//! is not established. The key and maximum age enter `Trust.issuer`, which
//! the order pins. This profile is a signed-response demonstration.
use alipay::RSAPubkey;
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_payment_settlement::{Payment, PaymentEvidence, reference_from_hex};
use uc_trust::{
    ALSO_COPY_HOLDER,
    ALSO_MERCHANT,
    ANCHOR_NONE,
    Binding,
    bytes::{bytes_hash, decimal_u64},
    SET_BY_MERCHANT,
    SOURCE_PLATFORM,
    Trust,
};

mod tests;

/// The Alipay payment-settlement scheme id.
pub global SCHEME_ALIPAY: u32 = 61;

pub global DOMAIN_ALIPAY_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_ALIPAY_ISSUER_V1".as_bytes()) };
pub global DOMAIN_ALIPAY_PAYEE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_ALIPAY_PAYEE_V1".as_bytes()) };
pub global DOMAIN_ALIPAY_TRADE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_ALIPAY_TRADE_V1".as_bytes()) };

/// `Payment.asset` of every Alipay trade: `total_amount` is CNY yuan, which
/// the adapter reports in fen. The same value as the WeChat Pay adapter's.
pub global ASSET_CNY: Field = comptime { poseidon2_hash_bytes("ISO-4217:CNY".as_bytes()) };

/// The longest response age, in seconds, that an order can accept.
pub global MAX_RESPONSE_AGE: u64 = 300;

global U64_MAX: u64 = 0xffffffffffffffff;

/// The current platform-key identifier; not an authenticated merchant identity.
pub fn payee(modulus: [Field; 18]) -> Field {
    poseidon2_hash([DOMAIN_ALIPAY_PAYEE, poseidon2_hash(modulus)])
}

/// A signed trade-query response and the claims it must carry.
#[derive(Serialize, Deserialize)]
pub struct AlipayTradeQuery {
    /// The Alipay RSA-2048 response-signing modulus and Barrett parameters,
    /// from a trusted platform public key or certificate.
    pub modulus: [Field; 18],
    pub redc: [Field; 18],
    /// The longest age, in seconds, of the response at the anchor block.
    pub max_age: u64,
    /// The v3 envelope: decimal millisecond timestamp, nonce, raw body and
    /// signature limbs.
    pub timestamp: BoundedVec<u8, 20>,
    pub nonce: BoundedVec<u8, 128>,
    pub body: BoundedVec<u8, 512>,
    pub signature: [Field; 18],
    /// The claims that the body must carry exactly.
    pub trade_no: BoundedVec<u8, 64>,
    pub out_trade_no: [u8; 64],
    pub total_fen: u64,
}

impl AlipayTradeQuery {
    /// The trust root that this input pins: the key and the maximum age.
    pub fn issuer(self) -> Field {
        poseidon2_hash([
            DOMAIN_ALIPAY_ISSUER,
            poseidon2_hash(self.modulus),
            poseidon2_hash(self.redc),
            self.max_age as Field,
        ])
    }
}

impl PaymentEvidence for AlipayTradeQuery {
    let SCHEME: u32 = 61;

    fn verify(self, context: &mut PrivateContext) -> Payment {
        assert((self.max_age > 0) & (self.max_age <= MAX_RESPONSE_AGE), "Bad maximum age");
        let now = context.get_anchor_block_header().timestamp();
        assert(now <= U64_MAX / 1000, "Anchor time out of range");
        // Checks the decimal form, `issued <= now` and `now - issued <= max_age`, in ms.
        let _digest = alipay::verify_v3_response(
            self.timestamp,
            self.nonce,
            self.body,
            self.signature,
            RSAPubkey::<18>::new(self.modulus, self.redc),
            now * 1000,
            self.max_age * 1000,
        );
        alipay::assert_trade_query_claims(
            self.body,
            self.trade_no,
            BoundedVec::from_array(self.out_trade_no),
            self.total_fen,
        );
        // `verify_v3_response` checked the decimal form of the timestamp.
        let issued = decimal_u64(self.timestamp) / 1000;
        uc_trust::require_fresh(context, issued, self.max_age);
        Payment {
            trust: Trust {
                source: SOURCE_PLATFORM,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                // A merchant or authorized service provider can query trades;
                // a signed response can be passed to anyone.
                also_authorised: ALSO_MERCHANT | ALSO_COPY_HOLDER,
            },
            payment_id: poseidon2_hash([DOMAIN_ALIPAY_TRADE, bytes_hash(self.trade_no)]),
            payee: payee(self.modulus),
            asset: ASSET_CNY,
            amount: self.total_fen as u128,
            // The response time, in whole seconds: the query saw a completed
            // trade then. The profile does not parse `send_pay_date`.
            paid_at: issued,
            reference: Binding { value: reference_from_hex(self.out_trade_no), set_by: SET_BY_MERCHANT },
        }
    }
}
