// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a strict Ed25519 signature using supplied point hints bound to the encoded key and
// signature.
#[export]
pub fn ed25519_verify_18(
    key: [u8; 32],
    signature: [u8; 64],
    message: BoundedVec<u8, 18>,
    key_hint: crate::PointHint,
    signature_hint: crate::PointHint,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(message);
    crate::verify(key, signature, message, key_hint, signature_hint);
}
