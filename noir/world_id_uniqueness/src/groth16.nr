pub use runtime_verifier::{Hints, RawVerificationKey};

// Framework-neutral ABI adapters. Arrays serialize in Aztec without adding
// Aztec traits to the shared verifier's types or changing its source package.
pub fn decode_key<let N: u32>(raw: [[u128; 3]; 16 + 2 * N]) -> RawVerificationKey<N> {
    let mut ic = [[[0; 3]; 2]; N + 1];
    for i in 0..N + 1 {
        ic[i] = [raw[14 + 2 * i], raw[15 + 2 * i]];
    }
    RawVerificationKey {
        alpha: [raw[0], raw[1]],
        beta: [raw[2], raw[3], raw[4], raw[5]],
        gamma: [raw[6], raw[7], raw[8], raw[9]],
        delta: [raw[10], raw[11], raw[12], raw[13]],
        ic,
    }
}
pub fn decode_hints<let N: u32>(raw: [Field; 2799 + 4 * N]) -> Hints<N> {
    let mut l = [[0; 3]; 2];
    for i in 0..2 {
        for j in 0..3 {
            l[i][j] = checked_limb(raw[3 * i + j]);
        }
    }
    let mut magnitudes = [[0; 2]; N];
    let mut negative = [[false; 2]; N];
    for i in 0..N {
        for j in 0..2 {
            magnitudes[i][j] = raw[6 + 2 * i + j];
            let bit = raw[6 + 2 * N + 2 * i + j];
            assert(bit * (bit - 1) == 0, "Hint sign must be Boolean");
            negative[i][j] = bit == 1;
        }
    }
    let offset = 6 + 4 * N;
    let mut residue = [[0; 3]; 36];
    let mut accumulators = [[[0; 3]; 12]; 66];
    let mut quotient = [[0; 3]; 94];
    let mut block_residuals = [[0; 3]; 9];
    for i in 0..36 {
        for j in 0..3 {
            residue[i][j] = checked_limb(raw[offset + 3 * i + j]);
        }
    }
    for i in 0..66 {
        for k in 0..12 {
            for j in 0..3 {
                accumulators[i][k][j] = checked_limb(raw[offset + 108 + 36 * i + 3 * k + j]);
            }
        }
    }
    for i in 0..94 {
        for j in 0..3 {
            quotient[i][j] = checked_limb(raw[offset + 2484 + 3 * i + j]);
        }
    }
    for i in 0..9 {
        for j in 0..3 {
            block_residuals[i][j] = checked_limb(raw[offset + 2766 + 3 * i + j]);
        }
    }
    Hints { claimed_l: l, magnitudes, negative, residue, accumulators, quotient, block_residuals }
}
fn checked_limb(value: Field) -> u128 {
    let limb = value as u128;
    assert(value == limb as Field, "Hint limb range");
    limb
}
// Proof verification is groth16-verifier's `runtime_verifier`; this module only
// adapts its arguments and checks the returned key hash. World ID application
// policy is in the crate root.
//
// Precondition on `authorized_key`: a terminal caller passes a compiled constant
// or a value from authenticated storage (the aztec/world-id-v3 and world-id-v4
// gates read `inner_key`). A recursive producer may pass a private value only if it
// puts that value into its sole public statement (common::binding::groth16_statement)
// and every consumer recomputes that statement with its own stored key. This
// function alone does not bind the key: it compares two values that the caller
// supplies.
pub fn verify<let N: u32>(
    key: RawVerificationKey<N>,
    public_inputs: [Field; N],
    proof: [[u128; 3]; 8],
    hints: Hints<N>,
    authorized_key: Field,
) {
    assert(authorized_key != 0, "Zero Groth16 key");
    let actual = runtime_verifier::verify(key, public_inputs, proof, hints);
    assert(actual == authorized_key, "Unauthorized World ID verification key");
}

// common::binding::groth16_statement reimplements runtime_verifier::statement_id so
// that consumers need no curve dependencies; the two must agree exactly.
#[test]
fn groth16_statement_matches_runtime_verifier() {
    let context = std::hint::black_box([1, 2, 3, 4, 5, 6]);
    let key_hash = std::hint::black_box(11);
    let inputs = std::hint::black_box([7, 8, 9, 10]);
    assert(
        common::binding::groth16_statement(context, key_hash, inputs)
            == runtime_verifier::statement_id(context, key_hash, inputs),
    );
    let one = std::hint::black_box([12]);
    assert(
        common::binding::groth16_statement(context, key_hash, one)
            == runtime_verifier::statement_id(context, key_hash, one),
    );
}
