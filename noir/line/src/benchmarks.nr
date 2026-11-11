// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use oidc::{JwtInput, TrustedP256Key};

// Verify a LINE ID token against the expected channel, subject, nonce and time.
#[export]
pub(crate) fn line_verify(
    token: JwtInput<192, 1024, 86>,
    key: TrustedP256Key,
    channel_id: BoundedVec<u8, 32>,
    subject: BoundedVec<u8, 256>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(channel_id);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _claims = crate::verify_line(token, channel_id, subject, nonce, now, key);
}
