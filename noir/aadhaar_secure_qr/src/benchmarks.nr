// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{SecureQrInput, UPSTREAM_MAX_SIGNED_BYTES, verify};

// Verify a trusted Aadhaar Secure QR, enforce adult age and derive an application nullifier.
// Standalone statement for the native Aadhaar Secure QR verifier: a QR
// signed by the trusted issuer, issued at most three hours before `now`
// (15 minutes of future skew for anchor lag), holder at least 18 on the
// issuance date, and the per-application nullifier as the public output.
// An Aztec app contract would run the same calls inside the private function
// that performs its fixed effect, and push the nullifier.

global MAX_QR_AGE_SECONDS: u64 = 10800;
global MAX_FUTURE_SECONDS: u64 = 900;

#[export]
pub(crate) fn aadhaar_secure_qr_verify(
    expected_issuer_key_hash: Field,
    app_seed: Field,
    now: u64,
    input: SecureQrInput<UPSTREAM_MAX_SIGNED_BYTES>,
) -> Field {
    let qr = verify(input, expected_issuer_key_hash);
    qr.assert_fresh(now, MAX_QR_AGE_SECONDS, MAX_FUTURE_SECONDS);
    assert(qr.age_at_least(18), "Holder is younger than 18 on the issuance date");
    qr.nullifier(app_seed)
}
