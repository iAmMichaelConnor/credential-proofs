//! WeChat Pay adapter: a platform-signed APIv3 transaction-query response as
//! payment evidence (`uc_payment_settlement::PaymentEvidence`).
//!
//! `wechatpay::verify_response` checks the RSA-SHA256 platform signature over
//! `Wechatpay-Timestamp LF Wechatpay-Nonce LF body LF` and the response age;
//! `wechatpay::assert_payment_claims` binds `appid`, `mchid`,
//! `trade_state == "SUCCESS"`, `transaction_id`, `attach`, `payer.openid`,
//! `amount.total` and `amount.currency == "CNY"` to the same signed body.
//!
//! The merchant sets `attach` when it creates the WeChat order. Settlement
//! requires it to be the order reference in text form (64 lowercase hex
//! digits, `uc_payment_settlement::reference_from_hex`), reported as
//! `SET_BY_MERCHANT`. The supplied key and maximum age are not trusted by
//! themselves: they enter `Trust.issuer`, which the order pins.
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
use wechatpay::RSAPubkey;

mod tests;

/// The WeChat Pay scheme id.
pub global SCHEME_WECHATPAY: u32 = 11;

pub global DOMAIN_WECHATPAY_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_WECHATPAY_ISSUER_V1".as_bytes()) };
pub global DOMAIN_WECHATPAY_PAYEE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_WECHATPAY_PAYEE_V1".as_bytes()) };
pub global DOMAIN_WECHATPAY_TRANSACTION: Field =
    comptime { poseidon2_hash_bytes("MIKE_UC_WECHATPAY_TRANSACTION_V1".as_bytes()) };

/// `Payment.asset` of every WeChat Pay payment: the profile accepts CNY only,
/// with `amount.total` in fen.
pub global ASSET_CNY: Field = comptime { poseidon2_hash_bytes("ISO-4217:CNY".as_bytes()) };

/// The longest response age, in seconds, that an order can accept.
pub global MAX_RESPONSE_AGE: u64 = 300;

/// The merchant that the order names: Poseidon2(domain, appid, mchid).
pub fn payee(appid: BoundedVec<u8, 128>, mchid: BoundedVec<u8, 128>) -> Field {
    poseidon2_hash(
        [DOMAIN_WECHATPAY_PAYEE, bytes_hash(appid), bytes_hash(mchid)],
    )
}

/// A signed transaction-query response and the claims it must carry.
#[derive(Serialize, Deserialize)]
pub struct WechatpayPayment {
    /// The platform RSA-2048 modulus and Barrett parameters (18 limbs each),
    /// from a trusted certificate or key registry, never from the response.
    pub modulus: [Field; 18],
    pub redc: [Field; 18],
    /// The longest age, in seconds, of the response at the anchor block.
    pub max_age: u64,
    /// `Wechatpay-Timestamp` (decimal Unix seconds), `Wechatpay-Nonce`, the
    /// raw body and the `Wechatpay-Signature` limbs.
    pub timestamp: BoundedVec<u8, 20>,
    pub nonce: BoundedVec<u8, 128>,
    pub body: BoundedVec<u8, 1024>,
    pub signature: [Field; 18],
    /// The claims that the body must carry exactly.
    pub appid: BoundedVec<u8, 128>,
    pub mchid: BoundedVec<u8, 128>,
    pub transaction_id: BoundedVec<u8, 128>,
    pub openid: BoundedVec<u8, 128>,
    pub attach: [u8; 64],
    pub total_fen: u64,
}

impl WechatpayPayment {
    /// The trust root that this input pins: the key and the maximum age.
    pub fn issuer(self) -> Field {
        poseidon2_hash([
            DOMAIN_WECHATPAY_ISSUER,
            poseidon2_hash(self.modulus),
            poseidon2_hash(self.redc),
            self.max_age as Field,
        ])
    }
}

impl PaymentEvidence for WechatpayPayment {
    let SCHEME: u32 = 11;

    fn verify(self, context: &mut PrivateContext) -> Payment {
        assert((self.max_age > 0) & (self.max_age <= MAX_RESPONSE_AGE), "Bad maximum age");
        let now = context.get_anchor_block_header().timestamp();
        // Checks the decimal form, `issued <= now` and `now - issued <= max_age`.
        let _digest = wechatpay::verify_response(
            self.timestamp,
            self.nonce,
            self.body,
            self.signature,
            RSAPubkey::<18>::new(self.modulus, self.redc),
            now,
            self.max_age,
        );
        wechatpay::assert_payment_claims(
            self.body,
            self.appid,
            self.mchid,
            self.transaction_id,
            self.openid,
            BoundedVec::from_array(self.attach),
            self.total_fen,
        );
        // `verify_response` checked the decimal form of the timestamp.
        let issued = decimal_u64(self.timestamp);
        // Inclusion is limited to the response's freshness deadline.
        uc_trust::require_fresh(context, issued, self.max_age);
        Payment {
            trust: Trust {
                source: SOURCE_PLATFORM,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                // Only the merchant can query its orders; it can pass the
                // signed response to anyone.
                also_authorised: ALSO_MERCHANT | ALSO_COPY_HOLDER,
            },
            payment_id: poseidon2_hash(
                [DOMAIN_WECHATPAY_TRANSACTION, bytes_hash(self.transaction_id)],
            ),
            payee: payee(self.appid, self.mchid),
            asset: ASSET_CNY,
            amount: self.total_fen as u128,
            // The response time: the query saw a completed payment then, so
            // the payment happened at or before it. The profile does not
            // parse `success_time`.
            paid_at: issued,
            reference: Binding { value: reference_from_hex(self.attach), set_by: SET_BY_MERCHANT },
        }
    }
}
