// Pinned Aztec v6 HONK_ZK/noir-recursive format. No inner-verifier dependency.
pub global VK_FIELDS: u32 = 115;
pub global PROOF_FIELDS: u32 = 458;

// Key-binding rule (docs/world-id.md, "Recursive certificate boundary"). The backend
// binds `key` to `authorized_key` and the proof to `key`. The prover supplies all
// three, so this call grants authority only when `authorized_key` is one of:
// a compiled constant, a value read from authenticated contract storage, or a
// public input of the calling circuit that its verifier pins to an authorised
// producer. Never pass a private witness that nothing else constrains.
//
// The recursive verifier checks the transcript, sumcheck and key hash in the
// circuit. It does not compute the pairing: it returns pairing points that the
// backend propagates to the kernel and the final Chonk verifier. A proof whose last
// opening commitment is replaced by another curve point passes every check here
// and fails only at that deferred pairing check. Execution and local constraint
// checks therefore do not show that a certificate is valid.
pub fn verify(
    key: [Field; VK_FIELDS],
    proof: [Field; PROOF_FIELDS],
    statement: Field,
    authorized_key: Field,
) {
    assert(authorized_key != 0, "zero producer key");
    std::verify_proof_with_type(key, proof, [statement], authorized_key, 6);
}
