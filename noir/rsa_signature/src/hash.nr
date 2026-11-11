use crate::{KEY_LIMBS_1024, KEY_LIMBS_2048};
use poseidon::poseidon;

// Hash 18 x 120-bit limbs into a single Field - compatible with https://github.com/zkemail/zk-email-verify/blob/62dd54871857697a6f2fb9c0a8ea72e38c7eb293/packages/circuits/utils/hash.circom#L15
pub fn poseidon_large(limbs120x18: [Field; KEY_LIMBS_2048]) -> Field {
    let limbs121x17 = limbs120x18_to_limbs121x17(limbs120x18);
    let poseidon_input = fold_limbs121::<17, 9>(limbs121x17);
    poseidon::bn254::hash_9(poseidon_input)
}

// Compute 2^n as u128 (n is small: <= 121)
fn pow2_u128(n: u32) -> u128 {
    let mut result: u128 = 1;
    for _ in 0..n {
        result = result * 2;
    }
    result
}

// Build 17 contiguous 121-bit limbs from 18 x 120-bit limbs (little-endian).
// Each source limb is constrained to < 2^120 before its u128 cast.
pub fn limbs120x18_to_limbs121x17(limbs120x18: [Field; KEY_LIMBS_2048]) -> [Field; 17] {
    for j in 0..KEY_LIMBS_2048 {
        limbs120x18[j].assert_max_bit_size::<120>();
    }
    // Seventeen output limbs represent exactly 2057 bits. Reject discarded high bits.
    limbs120x18[17].assert_max_bit_size::<17>();
    let mut limbs121x17 = [0; 17];
    for j in 0..17 {
        let a0: u128 = limbs120x18[j] as u128;
        let a1: u128 = if j + 1 < KEY_LIMBS_2048 {
            limbs120x18[j + 1] as u128
        } else {
            0
        };

        // Compute lower contribution: a0 >> j  => a0 / 2^j
        let lower: u128 = a0 / pow2_u128(j);

        // Mask for (1 + j) bits from next limb: (2^(1+j)) - 1
        let high_mask: u128 = pow2_u128(1 + j) - 1;
        let take_from_next: u128 = a1 & high_mask;

        // Left shift by (120 - j): multiply by 2^(120 - j)
        let high: u128 = take_from_next * pow2_u128(120 - j);

        limbs121x17[j] = (lower + high) as Field;
    }
    limbs121x17
}

// Fold K x 121-bit limbs into K_out Poseidon inputs. Inputs are constrained to
// < 2^121, so each pair is below 2^242 and cannot wrap the BN254 field.
pub fn fold_limbs121<let K: u32, let K_out: u32>(limbs121: [Field; K]) -> [Field; K_out] {
    assert(K >= 1, "K must be >= 1");
    assert(K_out >= 1, "K_out must be >= 1");
    assert(K_out == (K + 1) / 2, "K_out must equal ceil(K/2)");
    for i in 0..K {
        limbs121[i].assert_max_bit_size::<121>();
    }

    let base_121 = 2.pow_32(121);
    let mut input = [0; K_out];
    for i in 0..K_out {
        if 2 * i + 1 >= K {
            input[i] = limbs121[2 * i];
        } else {
            input[i] = limbs121[2 * i] + base_121 * limbs121[2 * i + 1]; // 2 * i + 1 < K
        }
    }
    input
}

// Pad 1024-bit limbs (9 x 120-bit) to 2048-bit width (18 x 120-bit) by appending zero limbs.
pub fn pad_limbs_1024_to_2048(limbs120x9: [Field; KEY_LIMBS_1024]) -> [Field; KEY_LIMBS_2048] {
    let mut padded: [Field; KEY_LIMBS_2048] = [0; KEY_LIMBS_2048];
    for i in 0..KEY_LIMBS_1024 {
        padded[i] = limbs120x9[i];
    }
    padded
}

// Hash a 1024-bit key array by zero-padding to 2048-bit width and reusing poseidon_large.
pub fn poseidon_large_padded_1024(limbs120x9: [Field; KEY_LIMBS_1024]) -> Field {
    poseidon_large(pad_limbs_1024_to_2048(limbs120x9))
}

#[test]
fn test_direct_limb_conversions_accept_canonical_boundary_values() {
    let mut limbs: [Field; 18] = [0; 18];
    limbs[0] = ((1u128 << 120) - 1) as Field;
    let _ = limbs120x18_to_limbs121x17(limbs);

    let mut folded: [Field; 3] = [0; 3];
    folded[0] = ((1u128 << 121) - 1) as Field;
    let _ = fold_limbs121::<3, 2>(folded);
}

#[test(should_fail_with = "all to assert_max_bit_size")]
fn test_direct_120_bit_conversion_rejects_oversized_limb() {
    let mut limbs: [Field; 18] = [0; 18];
    limbs[0] = (1u128 << 120) as Field;
    let _ = limbs120x18_to_limbs121x17(limbs);
}

#[test(should_fail_with = "all to assert_max_bit_size")]
fn test_direct_121_bit_fold_rejects_oversized_limb() {
    let mut limbs: [Field; 2] = [0; 2];
    limbs[0] = (1u128 << 121) as Field;
    let _ = fold_limbs121::<2, 1>(limbs);
}

/// Preserve all 2160 source bits in eighteen 121-bit limbs (final limb is 103 bits).
/// Use this full-width API when the source is not known to fit the legacy 2057-bit hash domain.
pub fn limbs120x18_to_limbs121x18(limbs: [Field; 18]) -> [Field; 18] {
    for i in 0..18 {
        limbs[i].assert_max_bit_size::<120>();
    }
    let mut output = [0; 18];
    for j in 0..18 {
        let lower = (limbs[j] as u128) / pow2_u128(j);
        let next: u128 = if j + 1 < 18 { limbs[j + 1] as u128 } else { 0 };
        let high = (next & (pow2_u128(1 + j) - 1)) * pow2_u128(120 - j);
        output[j] = (lower + high) as Field;
    }
    output
}
#[test]
fn even_fold_preserves_every_limb() {
    let base = 2.pow_32(121);
    assert(fold_limbs121::<2, 1>([7, 11]) == [7 + base * 11]);
    assert(fold_limbs121::<4, 2>([1, 2, 3, 4]) == [1 + base * 2, 3 + base * 4]);
    assert(fold_limbs121::<1, 1>([9]) == [9]);
}
#[test(should_fail_with = "K_out must equal ceil(K/2)")]
fn fold_rejects_truncated_output_shape() {
    let _ = fold_limbs121::<4, 1>([1, 2, 3, 4]);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn legacy_conversion_rejects_high_bit_collision() {
    let mut limbs: [Field; 18] = [0; 18];
    limbs[17] = (1u128 << 17) as Field;
    let _ = limbs120x18_to_limbs121x17(limbs);
}
#[test]
fn full_width_conversion_preserves_high_bits() {
    let mut limbs: [Field; 18] = [0; 18];
    limbs[17] = (1u128 << 119) as Field;
    let converted = limbs120x18_to_limbs121x18(limbs);
    assert(converted[17] == (1u128 << 102) as Field);
    let mut boundary: [Field; 18] = [0; 18];
    boundary[17] = ((1u128 << 17) - 1) as Field;
    let legacy = limbs120x18_to_limbs121x17(boundary);
    let wide = limbs120x18_to_limbs121x18(boundary);
    for i in 0..17 {
        assert(legacy[i] == wide[i]);
    }
    assert(wide[17] == 0);
}
#[test]
fn full_width_maximum_and_legacy_odd_fold() {
    let maximum = ((1u128 << 120) - 1) as Field;
    let wide = limbs120x18_to_limbs121x18([maximum; 18]);
    for i in 0..17 {
        assert(wide[i] == ((1u128 << 121) - 1) as Field);
    }
    assert(wide[17] == ((1u128 << 103) - 1) as Field);
    let input: [Field; 17] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
    let folded = fold_limbs121::<17, 9>(input);
    let base = 2.pow_32(121);
    for i in 0..8 {
        assert(folded[i] == input[2 * i] + base * input[2 * i + 1]);
    }
    assert(folded[8] == 17);
}
