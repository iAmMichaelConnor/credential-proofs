// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Decode canonical base64url into a bounded public byte string.
#[export]
pub(crate) fn base64url_decode_344(encoded: BoundedVec<u8, 344>) -> BoundedVec<u8, 258> {
    crate::decode_canonical(encoded, "non-canonical base64url encoding")
}
