//! Prove knowledge of a secp256k1 scalar corresponding to an Ethereum address.
use bignum::{BigNum, Secp256k1_Fr};
use noir_bigcurve::{BigCurve, Secp256k1};

// This fixed-base ladder uses the BigCurve complete `Add` implementation,
// not its offset-based `mul`, whose incomplete formulas can reject adversarial
// scalars that collide with the fixed public offsets. Input byte order is big
// endian; the prior Secp256k1_Fr range check binds these exact 256 bits to
// 1 <= scalar < n.
// BigCurve's Jacobian operations are unconstrained hints; constrained affine
// relations check the selected add, double, inverse and infinity cases.
// Secp256k1 has prime order n and cofactor one, so a nonidentity point with
// y = 0 (order two) cannot exist; the only such ladder state is the identity,
// which `Add` handles explicitly. The ladder itself reduces modulo n, so the
// tests pair n + 1 and 2^256 - 1 with the address of their residue: only the
// range check rejects them.
fn multiply_generator(secret_key: [u8; 32]) -> Secp256k1 {
    let generator = Secp256k1::one();
    let mut result = Secp256k1::point_at_infinity();
    for byte_index in 0..32 {
        for bit_index in 0..8 {
            result = result + result;
            let bit = ((secret_key[byte_index] >> (7 - bit_index)) & 1) == 1;
            if bit {
                result = result + generator;
            }
        }
    }
    result
}

/// Check that `secret_key` is a nonzero canonical secp256k1 scalar and its
/// generator multiple hashes to `expected_address`.
///
/// This proves key knowledge and address binding. It does not sign a message,
/// enforce EIP-191, or establish ownership/authorization policy for the address.
pub fn assert_secret_key_for_address(secret_key: [u8; 32], expected_address: [u8; 20]) {
    let scalar = Secp256k1_Fr::from_be_bytes(secret_key);
    scalar.validate_in_field();
    assert(scalar != Secp256k1_Fr::zero(), "secret key is zero");

    let public_key = multiply_generator(secret_key);
    assert(!public_key.is_infinity);
    public_key.x.validate_in_field();
    public_key.y.validate_in_field();
    let public_key_x = public_key.x.to_be_bytes();
    let public_key_y = public_key.y.to_be_bytes();
    let address = crate::eip191::ethereum_address(public_key_x, public_key_y);
    for i in 0..20 {
        assert_eq(address[i], expected_address[i], "address does not match the secret key");
    }
}

#[test]
fn fixed_base_ladder_handles_zero_and_last_valid_scalar() {
    let subgroup_order_minus_one = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    let result = multiply_generator(subgroup_order_minus_one);
    assert(result.eq(-Secp256k1::one()));
    assert(multiply_generator([0; 32]).is_infinity());
}

#[test]
fn proves_private_scalar_one_binds_to_its_ethereum_address() {
    let secret_key = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1,
    ];
    let expected_address = [
        0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65,
        0x90, 0x29, 0x39, 0x5b, 0xdf,
    ];
    assert_secret_key_for_address(secret_key, expected_address);
}

#[test(should_fail_with = "secret key is zero")]
fn rejects_zero_private_scalar() {
    assert_secret_key_for_address([0; 32], [0; 20]);
}

#[test(should_fail_with = "assert_is_not_zero_integer fail")]
fn rejects_secp256k1_subgroup_order_as_noncanonical() {
    let subgroup_order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    assert_secret_key_for_address(subgroup_order, [0; 20]);
}

// Non-canonical encodings. The ladder uses the raw 256 bits, so it computes
// (sk mod n) * G. Each case below pairs a value sk >= n with the address of its
// residue sk - n. The address check and the nonzero and infinity checks pass
// for these inputs, so only the canonical-scalar range check rejects them.
// Addresses come from viem `privateKeyToAccount` on the residue key.
global SUBGROUP_ORDER_PLUS_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x42,
];
// Address of key 1, the residue of n + 1.
global ADDRESS_OF_ONE: [u8; 20] = [
    0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65, 0x90,
    0x29, 0x39, 0x5b, 0xdf,
];
// 2^256 - 1 - n = 0x14551231950b75fc4402da1732fc9bebe, the residue of 2^256 - 1.
global FULL_WIDTH_RESIDUE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xbe,
];
// Address of FULL_WIDTH_RESIDUE (0xb92702b3EeFB3c2049aEB845B0335b283e11E9c6).
global ADDRESS_OF_FULL_WIDTH_RESIDUE: [u8; 20] = [
    0xb9, 0x27, 0x02, 0xb3, 0xee, 0xfb, 0x3c, 0x20, 0x49, 0xae, 0xb8, 0x45, 0xb0, 0x33, 0x5b, 0x28,
    0x3e, 0x11, 0xe9, 0xc6,
];

#[test]
fn ladder_reduces_noncanonical_scalars_modulo_the_subgroup_order() {
    // Shows that the ladder alone would accept sk + n as key sk.
    assert(multiply_generator(SUBGROUP_ORDER_PLUS_ONE).eq(Secp256k1::one()));
    assert(multiply_generator([0xff; 32]).eq(multiply_generator(FULL_WIDTH_RESIDUE)));
}

#[test]
fn accepts_the_full_width_residue_with_its_address() {
    assert_secret_key_for_address(FULL_WIDTH_RESIDUE, ADDRESS_OF_FULL_WIDTH_RESIDUE);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_subgroup_order_plus_one_with_the_address_of_one() {
    assert_secret_key_for_address(SUBGROUP_ORDER_PLUS_ONE, ADDRESS_OF_ONE);
}

// Supplies the residue's address, so the rejection is the range check, not
// the address comparison.
#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_full_width_integer_with_the_address_of_its_residue() {
    assert_secret_key_for_address([0xff; 32], ADDRESS_OF_FULL_WIDTH_RESIDUE);
}

#[test(should_fail_with = "address does not match the secret key")]
fn rejects_a_different_address_for_the_secret_scalar() {
    let secret_key = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1,
    ];
    assert_secret_key_for_address(secret_key, [0; 20]);
}
