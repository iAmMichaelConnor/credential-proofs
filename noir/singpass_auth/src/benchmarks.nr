// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Authorise a Singpass ID token against the supplied issuer key, policy and nonce.
#[export]
pub(crate) fn singpass_authorise(
    token: crate::AuthInput,
    key: p256::TrustedP256Key,
    policy: crate::AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(policy.audience);
    canonical_bytes::assert_canonical(policy.subject);
    canonical_bytes::assert_canonical(nonce);
    let _claims = crate::authorise(token, key, policy, nonce, now);
}
