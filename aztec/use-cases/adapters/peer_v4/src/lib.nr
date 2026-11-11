//! Peer V4 adapter: a Peer UnifiedPaymentVerifier V4 payment attestation as
//! payment evidence (`uc_payment_settlement::PaymentEvidence`).
//!
//! `peer_v4_auth::verify_peer_v4` checks the attestor's EIP-712 signature
//! over (intent hash, release amount, data hash), `keccak256(data)`, the
//! canonical ABI layout of (PaymentDetails, IntentSnapshot, settlementData),
//! the snapshot's agreement with the payment details, and the payment age.
//! The adapter takes the library's expected values from the signed data
//! itself, and reports the payment details to the core: the order pins the
//! method and payee, the currency, the fiat amount and the intent.
//!
//! Reference: the Peer intent hash, which the Base orchestrator assigns to
//! the intent that the payer signals. No Peer field can carry an Aztec
//! reference, so the order pins the intent hash as `external_reference`
//!: it is unique per Peer intent but does not name the
//! contract. The attestor, chain, verifier and maximum age enter
//! `Trust.issuer`, which the order pins.
//!
//! The same attestation also releases the intent's escrow on Base: this
//! settlement is in addition to Peer's own.
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use peer_v4_auth::{PeerV4Attestation, PeerV4Policy, verify_peer_v4};
use std::meta::derive;
use uc_payment_settlement::{Payment, PaymentEvidence};
use uc_trust::{
    ALSO_ATTESTOR, ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, bytes::halves, SET_BY_PAYER, SOURCE_ATTESTOR, Trust,
};

mod tests;

/// The Peer V4 scheme id.
pub global SCHEME_PEER_V4: u32 = 10;

pub global DOMAIN_PEER_ISSUER: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PEER_V4_ISSUER_V1".as_bytes()) };
pub global DOMAIN_PEER_PAYEE: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PEER_V4_PAYEE_V1".as_bytes()) };
pub global DOMAIN_PEER_CURRENCY: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PEER_V4_CURRENCY_V1".as_bytes()) };
pub global DOMAIN_PEER_PAYMENT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_PEER_V4_PAYMENT_V1".as_bytes()) };

/// The capacity of the ABI-encoded attestation data.
pub global DATA_CAPACITY: u32 = 1024;

/// The longest payment age, in milliseconds, that an order can accept.
pub global MAX_PAYMENT_AGE_MS: u64 = 86_400_000;

fn word_hash(domain: Field, a: [u8; 32], b: [u8; 32]) -> Field {
    let (a_high, a_low) = halves(a);
    let (b_high, b_low) = halves(b);
    poseidon2_hash([domain, a_high, a_low, b_high, b_low])
}

/// The payee that the order names: the Peer payment method and payee id
/// (both 32-byte Peer hashes).
pub fn payee(method: [u8; 32], payee_id: [u8; 32]) -> Field {
    word_hash(DOMAIN_PEER_PAYEE, method, payee_id)
}

/// The asset that the order names: the Peer fiat currency hash.
pub fn asset(currency: [u8; 32]) -> Field {
    word_hash(DOMAIN_PEER_CURRENCY, currency, [0; 32])
}

/// A 32-byte word as a canonical field element (the Peer intent hash is
/// reduced modulo the BN254 scalar field by the Base orchestrator).
pub fn canonical_field(word: [u8; 32]) -> Field {
    let value = Field::from_be_bytes::<32>(word);
    assert(value.to_be_bytes::<32>() == word, "Intent hash is not a field element");
    value
}

fn word_u128(word: [u8; 32]) -> u128 {
    for i in 0..16 {
        assert_eq(word[i], 0, "Amount exceeds u128");
    }
    let mut value: u128 = 0;
    for i in 16..32 {
        value = value * 256 + word[i] as u128;
    }
    value
}

fn word_u64(word: [u8; 32]) -> u64 {
    for i in 0..24 {
        assert_eq(word[i], 0, "Time exceeds u64");
    }
    let mut value: u64 = 0;
    for i in 24..32 {
        value = value * 256 + word[i] as u64;
    }
    value
}

fn read_word(data: [u8; DATA_CAPACITY], index: u32) -> [u8; 32] {
    let mut word = [0; 32];
    for i in 0..32 {
        word[i] = data[index * 32 + i];
    }
    word
}

/// A Peer V4 attestation with the attestor and deployment it must verify under.
#[derive(Serialize, Deserialize)]
pub struct PeerV4Payment {
    /// The Peer deployment: EIP-712 chain id and verifier contract.
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
    /// The attestor (witness) key and its Ethereum address.
    pub attestor_x: [u8; 32],
    pub attestor_y: [u8; 32],
    pub attestor_address: [u8; 20],
    /// The longest payment age at the anchor block, in milliseconds.
    pub max_payment_age_ms: u64,
    /// The signed `PaymentAttestation` and its ABI-encoded data.
    pub intent_hash: [u8; 32],
    pub release_amount: [u8; 32],
    pub data_hash: [u8; 32],
    pub data: [u8; DATA_CAPACITY],
    pub data_len: u32,
    pub signature: [u8; 65],
}

impl PeerV4Payment {
    /// The trust root that this input pins: deployment, attestor, maximum age.
    pub fn issuer(self) -> Field {
        let mut verifier: Field = 0;
        let mut attestor: Field = 0;
        for i in 0..20 {
            verifier = verifier * 256 + self.verifier_address[i] as Field;
            attestor = attestor * 256 + self.attestor_address[i] as Field;
        }
        poseidon2_hash([
            DOMAIN_PEER_ISSUER,
            self.chain_id as Field,
            verifier,
            attestor,
            self.max_payment_age_ms as Field,
        ])
    }
}

impl PaymentEvidence for PeerV4Payment {
    let SCHEME: u32 = 10;

    fn verify(self, context: &mut PrivateContext) -> Payment {
        assert((self.max_payment_age_ms > 0) & (self.max_payment_age_ms <= MAX_PAYMENT_AGE_MS), "Bad maximum age");
        let data = self.data;
        // The library compares each policy value with the signed data; the
        // order, not this policy, pins what the settlement needs.
        let policy = PeerV4Policy {
            chain_id: self.chain_id,
            verifier_address: self.verifier_address,
            attestor_x: self.attestor_x,
            attestor_y: self.attestor_y,
            attestor_address: self.attestor_address,
            expected_intent_hash: self.intent_hash,
            expected_method: read_word(data, 0),
            expected_payee_id: read_word(data, 1),
            expected_currency: read_word(data, 3),
            expected_token_amount: read_word(data, 7),
            expected_conversion_rate: read_word(data, 11),
            expected_signal_timestamp_ms: read_word(data, 12),
            expected_timestamp_buffer_ms: read_word(data, 13),
            expected_payer_commitment_hash: read_word(data, 14),
            expected_release_amount: self.release_amount,
            min_fiat_amount: read_word(data, 2),
            max_payment_age_ms: self.max_payment_age_ms,
        };
        let now = context.get_anchor_block_header().timestamp();
        let verified = verify_peer_v4(
            PeerV4Attestation {
                intent_hash: self.intent_hash,
                release_amount: self.release_amount,
                data_hash: self.data_hash,
                data,
                data_len: self.data_len,
                signature: self.signature,
            },
            policy,
            now,
        );
        let paid_ms = word_u64(verified.payment_timestamp_ms);
        assert(paid_ms <= 0xffffffffffffffff - self.max_payment_age_ms, "Payment time out of range");
        // Peer's own rule, which the policy does not pin: the payment is
        // not earlier than the intent's signal time minus its buffer, so an
        // old payment to the same payee cannot be attested for a new intent.
        let signal_ms = word_u64(read_word(data, 12));
        let buffer_ms = word_u64(read_word(data, 13));
        assert((paid_ms as u128) + (buffer_ms as u128) >= signal_ms as u128, "Payment before the Peer intent");
        // Inclusion is limited to the payment's freshness deadline (the
        // library checked it at the anchor block, in milliseconds).
        context.set_expiration_timestamp((paid_ms + self.max_payment_age_ms) / 1000);
        let (null_high, null_low) = halves(verified.nullifier);
        Payment {
            trust: Trust {
                source: SOURCE_ATTESTOR,
                issuer: self.issuer(),
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: ALSO_ATTESTOR | ALSO_COPY_HOLDER,
            },
            // Peer's own payment nullifier, keccak256(method || paymentId).
            payment_id: poseidon2_hash([DOMAIN_PEER_PAYMENT, null_high, null_low]),
            payee: payee(verified.method, verified.payee_id),
            asset: asset(verified.currency),
            amount: word_u128(verified.fiat_amount),
            paid_at: paid_ms / 1000,
            reference: Binding { value: canonical_field(verified.intent_hash), set_by: SET_BY_PAYER },
        }
    }
}
