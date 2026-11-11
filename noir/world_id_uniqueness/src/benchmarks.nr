// Benchmark entry points: the Groth16 producer circuits for World ID 3 (4 public
// inputs) and World ID 4 (15 public inputs). A producer verifies the World ID proof
// under `authorized_key` and returns its sole public output, the application
// statement that a recursive consumer recomputes with its own stored key.
// `nargo export` compiles each to its own program for the gates report.
use crate::groth16::{Hints, RawVerificationKey};

#[export]
fn world_id_groth16_producer_4(
    context: [Field; 6],
    key: RawVerificationKey<4>,
    proof: [[u128; 3]; 8],
    hints: Hints<4>,
    authorized_key: Field,
    public_inputs: [Field; 4],
) -> Field {
    crate::groth16::verify(key, public_inputs, proof, hints, authorized_key);
    common::binding::groth16_statement(context, authorized_key, public_inputs)
}

#[export]
fn world_id_groth16_producer_15(
    context: [Field; 6],
    key: RawVerificationKey<15>,
    proof: [[u128; 3]; 8],
    hints: Hints<15>,
    authorized_key: Field,
    public_inputs: [Field; 15],
) -> Field {
    crate::groth16::verify(key, public_inputs, proof, hints, authorized_key);
    common::binding::groth16_statement(context, authorized_key, public_inputs)
}
