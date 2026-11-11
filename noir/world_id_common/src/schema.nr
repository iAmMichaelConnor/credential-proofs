pub global DOMAIN: Field = 0x50524f56454b49545f415a5445435f5631;
pub global VK_FIELDS: u32 = 115;
pub global PROOF_FIELDS: u32 = 458;

// Context = chain, version, consumer address, action, beneficiary, nonce.
pub fn statement<let N: u32>(context: [Field; 6], public_inputs: [Field; N]) -> Field {
    crate::binding::statement(context, public_inputs)
}

// The authorized UltraHonk VK commits to the fixed ProveKit key and verifier.
// v6 HONK_ZK format: 458 proof fields, including 8 accumulator fields.
pub fn verify_certificate(
    key: [Field; VK_FIELDS],
    proof: [Field; PROOF_FIELDS],
    statement: Field,
    authorized_key: Field,
) {
    crate::certificate::verify(key, proof, statement, authorized_key);
}
