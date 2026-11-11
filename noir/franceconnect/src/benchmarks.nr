// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use oidc::{JwtInput, TrustedP256Key};

// Verify a FranceConnect ID token and enforce the requested authentication assurance.
#[export]
pub fn franceconnect_v1_verify(
    token: JwtInput<192, 1024, 86>,
    key: TrustedP256Key,
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 256>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
    integration: bool,
    minimum_acr: u8,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _ = crate::verify_franceconnect(
        token,
        audience,
        subject,
        nonce,
        now,
        integration,
        minimum_acr,
        key,
    );
}

// Verify a FranceConnect v2 ID token and enforce the requested authentication assurance.
#[export]
pub fn franceconnect_v2_verify(
    token: JwtInput<192, 1024, 86>,
    key: TrustedP256Key,
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 256>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
    sandbox: bool,
    minimum_acr: u8,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _ = crate::verify_franceconnect_v2(
        token,
        audience,
        subject,
        nonce,
        now,
        sandbox,
        minimum_acr,
        key,
    );
}
