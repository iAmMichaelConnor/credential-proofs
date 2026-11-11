// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{assert_age_above_18, verify};

// Verify an Anon Aadhaar v2 adult-age proof bound to an issuer key and action signal.
//
// The known-answer inputs pin `expected_issuer_key_hash` to upstream
// `testPublicKeyHash` (`UPSTREAM_TEST_ISSUER_KEY_HASH`), whose private key is
// published. Anyone can sign a QR under it. Never copy that policy into a
// deployment; pin a checked UIDAI key hash there.
#[export]
pub fn anon_aadhaar_v2_verify(
    expected_issuer_key_hash: Field,
    expected_nullifier_seed: Field,
    action_signal: [u8; 32],
    min_timestamp: u64,
    max_timestamp: u64,
    signals: [Field; 9],
    raw: [[u128; 3]; 10],
    residue: [[u128; 3]; 36],
    components: [[Field; 2]; 9],
    accumulators: [[[u128; 3]; 12]; 66],
    quotient: [[u128; 3]; 76],
    block_residuals: [[u128; 3]; 9],
) -> Field {
    let nullifier = verify(
        signals,
        expected_issuer_key_hash,
        expected_nullifier_seed,
        action_signal,
        min_timestamp,
        max_timestamp,
        raw,
        residue,
        components,
        accumulators,
        quotient,
        block_residuals,
    );
    assert_age_above_18(signals);
    nullifier
}
