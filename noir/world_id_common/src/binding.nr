use poseidon::poseidon2::Poseidon2;
pub global DOMAIN: Field = 0x50524f56454b49545f415a5445435f5631;
// Preserve the original producer statement exactly. Context is chain, version,
// consumer, action, beneficiary, nonce; the producer VK binds the inner key.
pub fn statement<let N: u32>(context: [Field; 6], public_inputs: [Field; N]) -> Field {
    let mut fields = [0; N + 7];
    fields[0] = DOMAIN;
    for i in 0..6 {
        fields[i + 1] = context[i];
    }
    for i in 0..N {
        fields[i + 7] = public_inputs[i];
    }
    Poseidon2::hash(fields, N + 7)
}

// Wire-compatible with the shared runtime_schema::statement_id. Keep the
// lightweight consumer independent of the non-native key/curve dependencies.
//
// Groth16 producer boundary. A producer checks the supplied inner Groth16 key
// against `key_hash`, but the prover chooses both, so a producer proof exists for
// any key, including one whose trapdoor the prover knows. The key is bound only
// because `key_hash` is inside this statement, the producer's sole public input.
// Every consumer must recompute the statement with `key_hash` read from
// authenticated storage or a constant (create_variant.py reads `inner_key`), and
// verify the producer certificate against that statement. A consumer that takes
// the statement or `key_hash` from calldata or from the certificate accepts
// forged World ID proofs.
pub fn groth16_statement<let N: u32>(
    context: [Field; 6],
    key_hash: Field,
    public_inputs: [Field; N],
) -> Field {
    let mut fields = [0; N + 9];
    fields[0] = 0x4731365f52554e54494d455f563100 + 2;
    fields[1] = N as Field;
    fields[2] = key_hash;
    for i in 0..6 {
        fields[i + 3] = context[i];
    }
    for i in 0..N {
        fields[i + 9] = public_inputs[i];
    }
    Poseidon2::hash(fields, N + 9)
}

#[test]
fn test_groth16_statement_binds_the_inner_key() {
    // A producer certificate made under another inner key never matches the
    // statement that a consumer recomputes from its stored key.
    let context = std::hint::black_box([1, 2, 3, 4, 5, 6]);
    let inputs = std::hint::black_box([7, 8, 9, 10]);
    let stored = groth16_statement(context, 11, inputs);
    assert(stored != groth16_statement(context, 12, inputs));
    assert(stored != groth16_statement(context, 11 + (2 as Field).pow_32(200), inputs));
    assert(stored != groth16_statement(context, 0, inputs));
    // Generic ProveKit statements use a different domain and never collide.
    assert(stored != statement(context, inputs));
}
