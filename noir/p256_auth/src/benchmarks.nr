// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a P256 signature over a public digest with the native ECDSA black box.
// The signature uses the backend's low-S convention; full JOSE normalization is
// in the es256 composition. The digest is public so the proof names the signed
// message; with a private digest any signature under the key would satisfy it.
#[export]
pub(crate) fn p256_black_box_verify(
    x: [u8; 32],
    y: [u8; 32],
    signature: [u8; 64],
    digest: [u8; 32],
) {
    assert(std::ecdsa_secp256r1::verify_signature(x, y, signature, digest));
}
