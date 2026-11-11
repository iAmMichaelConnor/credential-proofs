// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{ReclaimClaim, ReclaimPolicy, verify_claim};

// Verify a Reclaim attestor claim bound to the expected provider, parameters and context.
// Generic bounded attestor envelope. Public expected context is caller policy;
// this relation does not claim current account authorization or a TLS proof.
#[export]
pub(crate) fn reclaim_verify_claim(
    claim: ReclaimClaim<8, 512, 256>,
    policy: ReclaimPolicy<8>,
    expected_context: [u8; 256],
    expected_context_len: u32,
    now: u64,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_zero_padded(policy.provider, policy.provider_len);
    canonical_bytes::assert_zero_padded(expected_context, expected_context_len);
    let _ = verify_claim(claim, policy, expected_context, expected_context_len, now);
}
