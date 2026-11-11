//! Canonical big-endian bytes and little-endian120-bit RSA limbs.
//! Signatures may have leading zero bytes; modulus export requires exact width.
pub fn rsa_bytes_to_limbs<let CAP: u32, let BYTES: u32, let LIMBS: u32>(
    bytes: BoundedVec<u8, CAP>,
) -> [u128; LIMBS] {
    assert(LIMBS == (BYTES * 8 + 119) / 120, "RSA limb shape mismatch");
    assert(bytes.len() == BYTES, "RSA byte length mismatch");
    let mut limbs = [0; LIMBS];
    for i in 0..LIMBS {
        for j in 0..15 {
            let k = i * 15 + j;
            if k < BYTES {
                limbs[i] += (bytes.storage()[BYTES - 1 - k] as u128) << ((j * 8) as u128);
            }
        }
    }
    limbs
}
pub fn rsa_modulus_bytes<let LIMBS: u32, let BYTES: u32>(limbs: [u128; LIMBS]) -> [u8; BYTES] {
    assert(LIMBS == (BYTES * 8 + 119) / 120, "RSA limb shape mismatch");
    for i in 0..LIMBS {
        if i < LIMBS - 1 {
            (limbs[i] as Field).assert_max_bit_size::<120>();
        } else {
            (limbs[i] as Field).assert_max_bit_size::<BYTES * 8 - (LIMBS - 1) * 120>();
        }
    }
    let mut bytes = [0; BYTES];
    for i in 0..BYTES {
        bytes[BYTES - 1 - i] = (limbs[i / 15] >> (((i % 15) * 8) as u128)) as u8;
    }
    assert(bytes[0] >= 128, "RSA modulus must have exact bit length");
    assert((bytes[BYTES - 1] & 1) == 1, "RSA modulus must be odd");
    bytes
}
/// Constrain trusted-key modulus limbs to the canonical shape of an odd modulus
/// of exactly BITS bits: limbs 0..LIMBS-2 below 2^120, the top limb in
/// [2^(t-1), 2^t) with t = BITS - 120*(LIMBS-1), and limb 0 odd. Canonical
/// limbs make the limb vector a function of the integer. This is the same
/// shape as rsa_modulus_bytes without the byte export.
pub fn assert_rsa_modulus_shape<let LIMBS: u32, let BITS: u32>(limbs: [u128; LIMBS]) {
    assert(LIMBS == (BITS + 119) / 120, "RSA limb shape mismatch");
    // limb0 = 2h + 1 with h < 2^119 iff limb0 is odd and below 2^120. For an
    // even limb0, (limb0 - 1) / 2 in the native field is at least (r - 1) / 2.
    (((limbs[0] as Field) - 1) / 2).assert_max_bit_size::<119>();
    for i in 1..LIMBS - 1 {
        (limbs[i] as Field).assert_max_bit_size::<120>();
    }
    let top_bit: Field = 2.pow_32((BITS - (LIMBS - 1) * 120 - 1) as Field);
    // top - 2^(t-1) < 2^(t-1) iff 2^(t-1) <= top < 2^t; a smaller top wraps.
    ((limbs[LIMBS - 1] as Field) - top_bit).assert_max_bit_size::<BITS - (LIMBS - 1) * 120 - 1>();
}
#[test]
fn encoding_roundtrip_top_limb_and_leading_zero_signature() {
    let mut bytes = [255; 256];
    bytes[0] = 128;
    bytes[255] = 1;
    let limbs = rsa_bytes_to_limbs::<256, 256, 18>(BoundedVec::from_array(bytes));
    assert(rsa_modulus_bytes::<18, 256>(limbs) == bytes);
    let zero = rsa_bytes_to_limbs::<256, 256, 18>(BoundedVec::from_array([0; 256]));
    assert(zero == [0; 18]);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn encoding_rejects_shadowed_limb() {
    let mut limbs = [0; 18];
    limbs[0] = (1 as u128) << 120;
    limbs[17] = 128;
    let _bytes = rsa_modulus_bytes::<18, 256>(limbs);
}
#[test(should_fail_with = "RSA modulus must have exact bit length")]
fn encoding_rejects_short_modulus() {
    let _bytes = rsa_modulus_bytes::<18, 256>([1; 18]);
}
#[test]
fn modulus_shape_accepts_extreme_canonical_limbs() {
    // Smallest and largest odd moduli of exactly 2048 and 4096 bits.
    let mut low = [0; 18];
    low[0] = 1;
    low[17] = 128;
    assert_rsa_modulus_shape::<18, 2048>(low);
    let mut high = [(1 << 120) - 1; 18];
    high[17] = 255;
    assert_rsa_modulus_shape::<18, 2048>(high);
    let mut low4096 = [0; 35];
    low4096[0] = 1;
    low4096[34] = 1 << 15;
    assert_rsa_modulus_shape::<35, 4096>(low4096);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn modulus_shape_rejects_even_modulus() {
    let mut limbs = [0; 18];
    limbs[0] = 2;
    limbs[17] = 128;
    assert_rsa_modulus_shape::<18, 2048>(limbs);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn modulus_shape_rejects_short_modulus() {
    let mut limbs = [(1 << 120) - 1; 18];
    limbs[17] = 127;
    assert_rsa_modulus_shape::<18, 2048>(limbs);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn modulus_shape_rejects_wide_top_limb() {
    let mut limbs = [0; 18];
    limbs[0] = 1;
    limbs[17] = 256;
    assert_rsa_modulus_shape::<18, 2048>(limbs);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn modulus_shape_rejects_low_limb_alias() {
    // Same integer as limbs [1, 1, 0, ..., 128] with limb 0 carrying 2^120.
    let mut limbs = [0; 18];
    limbs[0] = (1 << 120) + 1;
    limbs[17] = 128;
    assert_rsa_modulus_shape::<18, 2048>(limbs);
}
#[test(should_fail_with = "all to assert_max_bit_size")]
fn modulus_shape_rejects_middle_limb_alias() {
    let mut limbs = [0; 18];
    limbs[0] = 1;
    limbs[16] = 1 << 120;
    limbs[17] = 128;
    assert_rsa_modulus_shape::<18, 2048>(limbs);
}
