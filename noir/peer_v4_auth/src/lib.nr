//! Verifier for Peer/ZKP2P's UnifiedPaymentVerifier V4 EIP-712 envelope.
//!
//! This profile verifies one policy-pinned witness key and the exact V4 ABI
//! payload. It is a signature and payment-evidence adapter, not a Peer escrow
//! client: deployment policy must pin the Base chain, verifier contract,
//! attestor key, method, payee, currency, expected Peer intent, and freshness.
//! Current Peer attestations bind a Peer intent, not an arbitrary Aztec action.
//!
//! `verify_peer_v4` checks the EIP-712 domain (`UnifiedPaymentVerifier`,
//! version 1, chain ID, verifier address), the
//! `PaymentAttestation(bytes32 intentHash,uint256 releaseAmount,bytes32 dataHash)`
//! struct, `dataHash == keccak256(data)` with canonical ABI offsets, lengths and
//! zero padding, the policy fields and the fiat floor, and returns the
//! Peer-compatible payment nullifier `keccak256(method || paymentId)`. One
//! attestor key matches a threshold-one Simple/MultiAttestationVerifier; a
//! multisig deployment needs a threshold-aware adapter. Schema source:
//! zkp2p-contracts f1402703 (`UnifiedPaymentVerifierV4.sol`); no Solidity is
//! copied.
//!
//! Caller obligations:
//! - Payment evidence never authorizes an Aztec action: accept only an intent
//!   hash the consumer already pinned. The signed snapshot omits
//!   `Intent.owner`; verify intent ownership on Base independently if it matters.
//! - The freshness window is `now_ms - max_payment_age_ms <= timestamp <= now_ms`
//!   with `now_ms = now_seconds * 1000`; with an anchor-block time set
//!   `max_payment_age_ms` well above block lag plus proving time.
//! - The attestor/witness policy, verifier deployment and Base state are
//!   trusted. Fiat reversal, escrow status, key rotation and release into Aztec
//!   remain external settlement concerns.

use ethereum_auth::eip191::ethereum_address;
use keccak256::keccak256;

pub struct PeerV4Attestation<let MAX: u32> {
    pub intent_hash: [u8; 32],
    pub release_amount: [u8; 32],
    pub data_hash: [u8; 32],
    /// `abi.encode(PaymentDetails, IntentSnapshot, settlementData)`.
    pub data: [u8; MAX],
    pub data_len: u32,
    /// Peer `bytes` signature, r || s || v.
    pub signature: [u8; 65],
}

pub struct PeerV4Policy {
    pub chain_id: u64,
    pub verifier_address: [u8; 20],
    pub attestor_x: [u8; 32],
    pub attestor_y: [u8; 32],
    pub attestor_address: [u8; 20],
    pub expected_intent_hash: [u8; 32],
    pub expected_method: [u8; 32],
    pub expected_payee_id: [u8; 32],
    pub expected_currency: [u8; 32],
    pub expected_token_amount: [u8; 32],
    pub expected_conversion_rate: [u8; 32],
    pub expected_signal_timestamp_ms: [u8; 32],
    pub expected_timestamp_buffer_ms: [u8; 32],
    pub expected_payer_commitment_hash: [u8; 32],
    pub expected_release_amount: [u8; 32],
    pub min_fiat_amount: [u8; 32],
    pub max_payment_age_ms: u64,
}

pub struct VerifiedPayment {
    pub intent_hash: [u8; 32],
    pub method: [u8; 32],
    pub payee_id: [u8; 32],
    pub fiat_amount: [u8; 32],
    pub currency: [u8; 32],
    pub payment_timestamp_ms: [u8; 32],
    pub payment_id: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Verify a Peer V4 signature and extract the payment details after checking
/// all policy-relevant fields. `now_seconds` is an authenticated current time.
pub fn verify_peer_v4<let MAX: u32>(
    attestation: PeerV4Attestation<MAX>,
    policy: PeerV4Policy,
    now_seconds: u64,
) -> VerifiedPayment {
    assert(MAX >= 544);
    assert(attestation.data_len >= 544);
    assert(attestation.data_len <= MAX);
    assert_eq(
        attestation.intent_hash,
        policy.expected_intent_hash,
        "peer intent hash does not match policy",
    );
    assert_eq(attestation.release_amount, policy.expected_release_amount);

    // Canonical ABI layout of (PaymentDetails, IntentSnapshot, bytes):
    // 16 head words, dynamic bytes offset 512, length word, then padded bytes.
    let offset = read_word(attestation.data, 15);
    for i in 0..30 {
        assert_eq(offset[i], 0);
    }
    assert_eq(offset[30], 2);
    assert_eq(offset[31], 0);
    let settlement_len_word = read_word(attestation.data, 16);
    for i in 0..28 {
        assert_eq(settlement_len_word[i], 0);
    }
    let settlement_len = (settlement_len_word[28] as u32) * 256 + settlement_len_word[29] as u32;
    let settlement_len = settlement_len * 256 + settlement_len_word[30] as u32;
    let settlement_len = settlement_len * 256 + settlement_len_word[31] as u32;
    assert(settlement_len <= MAX - 544);
    let padded_len = ((settlement_len + 31) / 32) * 32;
    assert(attestation.data_len == 544 + padded_len);
    for i in 0..MAX {
        if (i >= 544 + settlement_len) & (i < attestation.data_len) {
            assert_eq(attestation.data[i], 0);
        }
    }

    let method = read_word(attestation.data, 0);
    let payee_id = read_word(attestation.data, 1);
    let fiat_amount = read_word(attestation.data, 2);
    let currency = read_word(attestation.data, 3);
    let payment_timestamp_ms = read_word(attestation.data, 4);
    let payment_id = read_word(attestation.data, 5);
    let snapshot_intent_hash = read_word(attestation.data, 6);
    let token_amount = read_word(attestation.data, 7);
    let snapshot_method = read_word(attestation.data, 8);
    let snapshot_currency = read_word(attestation.data, 9);
    let snapshot_payee = read_word(attestation.data, 10);
    let snapshot_time_buffer = read_word(attestation.data, 13);
    let snapshot_conversion_rate = read_word(attestation.data, 11);
    let snapshot_signal_timestamp = read_word(attestation.data, 12);
    let snapshot_payer_commitment = read_word(attestation.data, 14);

    assert_eq(method, policy.expected_method);
    assert_eq(payee_id, policy.expected_payee_id);
    assert_eq(currency, policy.expected_currency);
    assert_eq(token_amount, policy.expected_token_amount);
    assert_eq(snapshot_conversion_rate, policy.expected_conversion_rate);
    assert_eq(snapshot_signal_timestamp, policy.expected_signal_timestamp_ms);
    assert_eq(snapshot_time_buffer, policy.expected_timestamp_buffer_ms);
    assert_eq(snapshot_payer_commitment, policy.expected_payer_commitment_hash);
    assert_eq(snapshot_intent_hash, policy.expected_intent_hash);
    assert_eq(snapshot_method, method);
    assert_eq(snapshot_currency, currency);
    assert_eq(snapshot_payee, payee_id);
    assert(word_gte(fiat_amount, policy.min_fiat_amount));
    assert(!all_zero(payment_id));
    assert(!all_zero(fiat_amount));
    assert(!all_zero(attestation.release_amount));

    // Convert seconds without permitting u64 wraparound.
    assert(now_seconds <= 18_446_744_073_709_551);
    let now_ms = now_seconds * 1000;
    let payment_time = word_to_u64(payment_timestamp_ms);
    assert(payment_time <= now_ms, "peer payment is after the current time");
    assert(
        (now_ms - payment_time) <= policy.max_payment_age_ms,
        "peer payment is older than policy allows",
    );
    assert(word_to_u64(snapshot_time_buffer) <= 172_800_000);

    let hashed_data = keccak256(attestation.data, attestation.data_len);
    assert_eq(hashed_data, attestation.data_hash, "peer data hash mismatch");
    let digest = eip712_digest(attestation, policy);
    assert(
        (attestation.signature[64] == 0)
            | (attestation.signature[64] == 1)
            | (attestation.signature[64] == 27)
            | (attestation.signature[64] == 28),
    );

    let derived_address = ethereum_address(policy.attestor_x, policy.attestor_y);
    assert_eq(
        derived_address,
        policy.attestor_address,
        "peer attestor address does not match its key",
    );
    let mut rs: [u8; 64] = [0; 64];
    for i in 0..64 {
        rs[i] = attestation.signature[i];
    }
    assert(
        std::ecdsa_secp256k1::verify_signature(policy.attestor_x, policy.attestor_y, rs, digest),
        "peer attestor signature invalid",
    );

    let mut nullifier_input: [u8; 64] = [0; 64];
    for i in 0..32 {
        nullifier_input[i] = method[i];
        nullifier_input[32 + i] = payment_id[i];
    }
    let nullifier = keccak256(nullifier_input, 64);
    VerifiedPayment {
        intent_hash: attestation.intent_hash,
        method,
        payee_id,
        fiat_amount,
        currency,
        payment_timestamp_ms,
        payment_id,
        nullifier,
    }
}

fn eip712_digest<let MAX: u32>(
    attestation: PeerV4Attestation<MAX>,
    policy: PeerV4Policy,
) -> [u8; 32] {
    let domain_type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            .as_bytes(),
        82,
    );
    let name_hash = keccak256("UnifiedPaymentVerifier".as_bytes(), 22);
    let version_hash = keccak256("1".as_bytes(), 1);
    let mut domain_encoding: [u8; 160] = [0; 160];
    domain_encoding = put_word(domain_encoding, 0, domain_type_hash);
    domain_encoding = put_word(domain_encoding, 1, name_hash);
    domain_encoding = put_word(domain_encoding, 2, version_hash);
    let mut chain_word: [u8; 32] = [0; 32];
    let mut chain_value = policy.chain_id;
    for i in 0..8 {
        chain_word[31 - i] = (chain_value % 256) as u8;
        chain_value = chain_value / 256;
    }
    domain_encoding = put_word(domain_encoding, 3, chain_word);
    let mut address_word: [u8; 32] = [0; 32];
    for i in 0..20 {
        address_word[12 + i] = policy.verifier_address[i];
    }
    domain_encoding = put_word(domain_encoding, 4, address_word);
    let domain_separator = keccak256(domain_encoding, 160);

    let type_hash = keccak256(
        "PaymentAttestation(bytes32 intentHash,uint256 releaseAmount,bytes32 dataHash)".as_bytes(),
        77,
    );
    let mut struct_encoding: [u8; 160] = [0; 160];
    struct_encoding = put_word(struct_encoding, 0, type_hash);
    struct_encoding = put_word(struct_encoding, 1, attestation.intent_hash);
    struct_encoding = put_word(struct_encoding, 2, attestation.release_amount);
    struct_encoding = put_word(struct_encoding, 3, attestation.data_hash);
    let struct_hash = keccak256(struct_encoding, 128);
    let mut digest_encoding: [u8; 66] = [0; 66];
    digest_encoding[0] = 0x19;
    digest_encoding[1] = 0x01;
    for i in 0..32 {
        digest_encoding[2 + i] = domain_separator[i];
        digest_encoding[34 + i] = struct_hash[i];
    }
    keccak256(digest_encoding, 66)
}

fn read_word<let MAX: u32>(data: [u8; MAX], index: u32) -> [u8; 32] {
    let mut word: [u8; 32] = [0; 32];
    for i in 0..32 {
        word[i] = data[index * 32 + i];
    }
    word
}

fn put_word<let N: u32>(mut data: [u8; N], index: u32, word: [u8; 32]) -> [u8; N] {
    for i in 0..32 {
        data[index * 32 + i] = word[i];
    }
    data
}

fn all_zero(word: [u8; 32]) -> bool {
    let mut zero = true;
    for i in 0..32 {
        zero = zero & (word[i] == 0);
    }
    zero
}

fn word_to_u64(word: [u8; 32]) -> u64 {
    for i in 0..24 {
        assert_eq(word[i], 0);
    }
    let mut value = 0;
    for i in 24..32 {
        value = value * 256 + word[i] as u64;
    }
    value
}

fn word_gte(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut decided = false;
    let mut gte = true;
    for i in 0..32 {
        if !decided {
            if left[i] > right[i] {
                decided = true;
                gte = true;
            } else if left[i] < right[i] {
                decided = true;
                gte = false;
            }
        }
    }
    gte
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word: [u8; 32] = [0; 32];
    let mut remaining = value;
    for i in 0..8 {
        word[31 - i] = (remaining % 256) as u8;
        remaining = remaining / 256;
    }
    word
}

fn peer_fixture() -> (PeerV4Attestation<544>, PeerV4Policy) {
    let method = [
        0x3c, 0xcc, 0x3d, 0x4d, 0x5e, 0x76, 0x9b, 0x1f, 0x82, 0xdc, 0x49, 0x88, 0x48, 0x55, 0x51,
        0xdc, 0x0c, 0xd3, 0xc7, 0xa3, 0x92, 0x6d, 0x7d, 0x8a, 0x4d, 0xde, 0x91, 0x50, 0x71, 0x99,
        0x49, 0x0f,
    ];
    let payee = [
        0x49, 0x1e, 0xd0, 0x26, 0xad, 0xf1, 0x48, 0x0c, 0xa9, 0xb9, 0x0c, 0xb5, 0xd0, 0xee, 0x91,
        0x39, 0x23, 0x92, 0xaf, 0x92, 0x19, 0xa9, 0x65, 0x02, 0x44, 0x86, 0xc9, 0xd3, 0xc0, 0xf2,
        0xd7, 0xaf,
    ];
    let currency = [
        0xc4, 0xae, 0x21, 0xaa, 0xc0, 0xc6, 0x54, 0x9d, 0x71, 0xdd, 0x96, 0x03, 0x5b, 0x7e, 0x0b,
        0xdb, 0x6c, 0x79, 0xeb, 0xdb, 0xa8, 0x89, 0x1b, 0x66, 0x61, 0x15, 0xbc, 0x97, 0x6d, 0x16,
        0xa2, 0x9e,
    ];
    let intent = [
        0x6e, 0x40, 0x75, 0xc9, 0xa4, 0x14, 0xc4, 0x4a, 0xf6, 0x94, 0xab, 0x55, 0x5d, 0xa0, 0x77,
        0xfc, 0x91, 0x9f, 0x82, 0xb0, 0x2d, 0xf5, 0xea, 0xf7, 0x0a, 0x8c, 0xb1, 0x9c, 0x4c, 0xbd,
        0x0e, 0x45,
    ];
    let payment_id = [
        0x16, 0x02, 0x77, 0x8d, 0x35, 0x21, 0xa0, 0x13, 0x84, 0xc9, 0x0b, 0x32, 0xca, 0xac, 0x50,
        0xb9, 0x9d, 0x4c, 0xcc, 0x6e, 0x7d, 0x0b, 0x00, 0x7c, 0x18, 0x0b, 0xf3, 0xf6, 0x50, 0x70,
        0x2a, 0xf6,
    ];
    let mut data: [u8; 544] = [0; 544];
    data = put_word(data, 0, method);
    data = put_word(data, 1, payee);
    data = put_word(data, 2, word_u64(10_000));
    data = put_word(data, 3, currency);
    data = put_word(data, 4, word_u64(1_700_000_000_000));
    data = put_word(data, 5, payment_id);
    data = put_word(data, 6, intent);
    data = put_word(data, 7, word_u64(500));
    data = put_word(data, 8, method);
    data = put_word(data, 9, currency);
    data = put_word(data, 10, payee);
    data = put_word(data, 11, word_u64(1_000_000_000_000_000_000));
    data = put_word(data, 12, word_u64(1_700_000_000_000));
    data = put_word(data, 13, word_u64(60_000));
    data = put_word(data, 15, word_u64(512));
    data = put_word(data, 16, word_u64(0));
    let data_hash = [
        0x7b, 0x86, 0x90, 0xf7, 0xe5, 0x47, 0xbb, 0xd2, 0x7a, 0x5f, 0x53, 0x3f, 0xd9, 0xec, 0x23,
        0x72, 0x2b, 0xdd, 0x04, 0x06, 0x47, 0xf6, 0x3d, 0xe4, 0xae, 0x20, 0x65, 0xe6, 0x48, 0x15,
        0x0e, 0xe7,
    ];
    let signature = [
        0x57, 0xbc, 0xcb, 0xe3, 0xcf, 0xa7, 0xf7, 0x64, 0xbe, 0x6e, 0x69, 0xc5, 0x2d, 0x0c, 0x69,
        0x43, 0x1e, 0x54, 0xf4, 0x77, 0xee, 0x90, 0x3b, 0x66, 0x67, 0x8b, 0x88, 0x66, 0x3f, 0x22,
        0xce, 0xb2, 0x33, 0xa9, 0xd4, 0x79, 0x6a, 0x0d, 0xbd, 0x02, 0xff, 0x3c, 0x8a, 0x27, 0x87,
        0x09, 0x3b, 0xc2, 0xec, 0x54, 0x40, 0x4c, 0x04, 0xb6, 0xf8, 0xb9, 0xc5, 0x71, 0x76, 0xc1,
        0xd3, 0xde, 0x4d, 0xaa, 0x1b,
    ];
    let attestation = PeerV4Attestation::<544> {
        intent_hash: intent,
        release_amount: word_u64(400),
        data_hash,
        data,
        data_len: 544,
        signature,
    };
    let policy = PeerV4Policy {
        chain_id: 8453,
        verifier_address: [0x11; 20],
        attestor_x: [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ],
        attestor_y: [
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ],
        attestor_address: [
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
            0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
        ],
        expected_intent_hash: intent,
        expected_method: method,
        expected_payee_id: payee,
        expected_currency: currency,
        expected_token_amount: word_u64(500),
        expected_conversion_rate: word_u64(1_000_000_000_000_000_000),
        expected_signal_timestamp_ms: word_u64(1_700_000_000_000),
        expected_timestamp_buffer_ms: word_u64(60_000),
        expected_payer_commitment_hash: [0; 32],
        expected_release_amount: word_u64(400),
        min_fiat_amount: word_u64(10_000),
        max_payment_age_ms: 60_000,
    };
    (attestation, policy)
}

#[test]
fn verifies_peer_v4_eip712_signature_and_payment_binding() {
    let (attestation, policy) = peer_fixture();
    let verified = verify_peer_v4(attestation, policy, 1_700_000_000);
    assert_eq(verified.payment_id[0], 0x16);
    assert_eq(verified.fiat_amount[31], 0x10);
}

#[test(should_fail_with = "peer intent hash does not match policy")]
fn rejects_peer_intent_substitution() {
    let (attestation, mut policy) = peer_fixture();
    policy.expected_intent_hash[0] = 0;
    let _ = verify_peer_v4(attestation, policy, 1_700_000_000);
}

#[test(should_fail_with = "peer payment is older than policy allows")]
fn rejects_stale_peer_payment() {
    let (attestation, policy) = peer_fixture();
    let _ = verify_peer_v4(attestation, policy, 1_700_000_100);
}
mod benchmarks;
mod known_answer_tests;
