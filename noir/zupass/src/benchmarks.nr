// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{PublicKey, Signature};

// Verify membership of a named value hash in a signed Zupass POD content tree.
//
// Generic entry relation. The proof shows only that hash_2([name_hash,
// value_hash]) is a node on a path to the signed content ID. POD does not
// domain-separate leaves from inner nodes or from eddsa_pubkey value hashes, so
// the verifier MUST check that the public `name_hash` is `bytes_hash` of the
// expected name and that `value_hash` is the typed hash of the expected value.
// Otherwise the children of an inner node, or the coordinates of a public-key
// value, also verify. A composed circuit should use `assert_named_entry` and
// compute the value hash from a typed value.
#[export]
pub(crate) fn zupass_pod_entry(
    issuer: PublicKey,
    content_id: Field,
    signature: Signature,
    name_hash: Field,
    value_hash: Field,
    depth: u32,
    indices: [bool; 8],
    siblings: [Field; 8],
) {
    crate::assert_pod_signature(content_id, issuer, signature);
    crate::assert_entry(content_id, name_hash, value_hash, depth, indices, siblings);
}
