//! Fixed-key Anon Aadhaar v2 Groth16 verification and action binding.
//!
//! The public signal order is the upstream circuit order:
//! `[pubkeyHash, nullifier, timestamp, ageAbove18, gender, pinCode, state,
//! nullifierSeed, signalHash]`.
//!
//! `application_key` is the generated fixed verification key of the published
//! upstream v2.0.0 key (anon-aadhaar@4dad918, `AadhaarQRVerifier(121, 17,
//! 1536)`, nine public inputs; the key embedded in the `.zkey` matches the
//! published JSON key, SHA-256 `40f2ea24...cf177`), with the
//! `groth16-fixed-global68-v1` hint geometry (66 pairing accumulators, 76-limb
//! quotient). Replace it only by regenerating it with the Groth16 source
//! generator from the upstream key in the credential material. The key is a
//! compile-time constant with no rotation path. Soundness of malformed hints
//! rests on the Groth16 library's quadratic-relation and carry checks, not on
//! an honest execution rejecting them.
//!
//! Caller obligations:
//! - Issuer hash, nullifier seed, signal and timestamp window come from trusted
//!   state; pin a checked current UIDAI key hash.
//! - The signal is a free prover input: anyone with a copy of the QR chooses it.
//!   It binds a proof to its submitter or context, not to the holder's approval,
//!   so this is not account authorization. Fix the effect and consume the
//!   returned credential nullifier once per scope; an action-scoped replay key
//!   would let one QR authorize any number of actions.
//! - Revealed claims mean something only when their upstream reveal flags were
//!   enabled. After 2032 use a corrected upstream circuit and key, or the native
//!   `aadhaar_secure_qr` verifier.

pub mod application_key;
pub mod issuance_time;

/// Upstream `testPublicKeyHash` (packages/core/src/constants.ts at 4dad918):
/// the `pubkeyHash` of the test key that signs the public test QR. Upstream
/// publishes its private key (packages/circuits/assets/testPrivateKey.pem), so
/// anyone can sign a QR with any fields under it. Never trust it outside
/// tests.
pub global UPSTREAM_TEST_ISSUER_KEY_HASH: Field =
    15134874015316324267425466444584014077184337590635665158241104437045239495873;
/// Upstream `productionPublicKeyHash`: the `pubkeyHash` of UIDAI
/// `uidai_offline_publickey_26022021.cer`, which expired on 2024-02-27. UIDAI
/// rotates its key; a deployer must check and pin the current one.
pub global UIDAI_2021_ISSUER_KEY_HASH: Field =
    18063425702624337643644061197836918910810808173893535653269228433734128853484;

use application_key::AnonAadhaarV2Key;
use keccak256::keccak256;

/// Compute the Anon Aadhaar SDK's `hash(signal)` commitment:
/// `uint256(keccak256(bytes32(signal))) >> 3`.
///
/// The SDK accepts a 256-bit numeric signal, not a Noir field element. Keep
/// all 32 bytes so values above the scalar modulus are not silently reduced.
pub fn hash_signal(signal: [u8; 32]) -> Field {
    let digest = keccak256(signal, 32);
    let mut shifted: [u8; 32] = [0; 32];
    for i in 0..32 {
        let carry = if i == 0 {
            0
        } else {
            (digest[i - 1] & 0x07) << 5
        };
        shifted[i] = (digest[i] >> 3) | carry;
    }
    Field::from_be_bytes(shifted)
}

/// Require the upstream `revealAgeAbove18` output. The pinned circuit sets this
/// signal only when revealed whole-year age is strictly greater than 18. Zero
/// can mean the claim was not revealed or age was at most 18.
pub fn assert_age_above_18(signals: [Field; 9]) {
    assert_eq(signals[3], 1, "Age claim was not revealed or is not strictly greater than 18");
}

/// Verify an Anon Aadhaar v2 proof and bind it to application-controlled
/// policy. The policy values must come from trusted caller state, not from the
/// proof submitter.
///
/// `expected_issuer_key_hash` must be the hash of a key that the deployer
/// trusts, never `UPSTREAM_TEST_ISSUER_KEY_HASH` outside tests.
///
/// `min_timestamp..=max_timestamp` is an application freshness window in
/// Unix seconds, compared with the raw `signals[2]`. The upstream extractor
/// sets issuance minutes and seconds to zero, so its timestamp is truncated to
/// the start of the issuance hour in IST before conversion to Unix seconds. A
/// policy window shorter than one hour can reject a freshly issued QR depending
/// on its issuance minute. Through 2032-02-29 IST the signal is exact; for an
/// issuance from 2032-03-01 to 2032-12-31 IST it is 86400 s early, and the
/// official witness generator refuses later years (see `issuance_time`).
/// This function checks the supplied bounds explicitly; it adds no hour or
/// day of tolerance. Choose bounds from a trusted clock or application policy,
/// or check `issuance_time::issuance_hour_bounds(signals[2] as u64)` against
/// the window instead. The returned value is the proof's nullifier for the
/// caller to consume in its replay-prevention state.
pub fn verify(
    signals: [Field; 9],
    expected_issuer_key_hash: Field,
    expected_nullifier_seed: Field,
    action_signal: [u8; 32],
    min_timestamp: u64,
    max_timestamp: u64,
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 9],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) -> Field {
    assert(min_timestamp <= max_timestamp, "Invalid timestamp window");
    assert_eq(signals[0], expected_issuer_key_hash, "Wrong issuer key");
    assert_eq(signals[7], expected_nullifier_seed, "Wrong nullifier seed");
    assert_eq(signals[8], hash_signal(action_signal), "Wrong action signal");

    let timestamp = signals[2] as u64;
    assert_eq(signals[2], timestamp as Field, "QR timestamp exceeds u64");
    assert(timestamp >= min_timestamp, "QR is too old");
    assert(timestamp <= max_timestamp, "QR timestamp is in the future");

    groth16::verify::<AnonAadhaarV2Key, 9>(
        signals,
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
    signals[1]
}

// keccak256(bytes32(0)) and keccak256(bytes32(1)) are the well-known Ethereum
// constants 0x290decd9...e563 and 0xb10e2d52...0cf6; each expected value is
// that digest shifted right by three bits.
#[test]
fn hash_signal_matches_shifted_keccak_vectors() {
    assert_eq(
        hash_signal([0; 32]),
        0x521bd9b2a916c551ac068b531070df90974d792a908011ec6c5f262c1de7cac,
    );
    let mut one = [0; 32];
    one[31] = 1;
    assert_eq(hash_signal(one), 0x1621c5aa4ec240e764ddd9bfae2fcd46419e89695f58560e65b3f97c56ff419e);
}

#[test(should_fail_with = "Age claim was not revealed or is not strictly greater than 18")]
fn age_claim_requires_the_revealed_signal() {
    assert_age_above_18([0; 9]);
}
pub mod benchmarks;
