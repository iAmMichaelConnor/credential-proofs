// Modified copy of https://github.com/willemolding/noir-ed25519 v0.1.0-alpha.1
// (e525bf21215b0ec664f50cf6234bf6574f498c5c), Apache-2.0: see ../LICENSE.
// Changes: the cofactored `ed25519_verify` is replaced by
// `ed25519_verify_prime_subgroup`, scalars use ScalarField<63>, and the
// upstream test and benchmark modules are removed.
use std::ops::Neg;

use bignum::{bignum::BigNum, ED25519_Fr as Fr};
use edwards_bignum::{CurveTrait, ScalarField, TECurveParameterTrait};
use edwards_bignum::ed25519::{Ed25519, Ed25519Params};
use sha512::sha512;

/// Modified workspace API, not upstream cofactored verification semantics.
/// PRECONDITION: caller MUST constrain A and R to the subgroup of order ell,
/// and bind canonical encodings/scalar bytes. The strict workspace wrapper does.
pub fn ed25519_verify_prime_subgroup<let MSG_MAX_LEN: u32>(
    pubkey: Ed25519,
    sig_scalar: Field,
    sig_point: Ed25519,
    message: BoundedVec<u8, MSG_MAX_LEN>,
) -> bool {
    pubkey.assert_is_on_curve();
    sig_point.assert_is_on_curve();

    // Reject small-order / identity public keys: 8A == O iff ord(A) divides the
    // cofactor (8), so this rules out all torsion-only keys, for which the check
    // below would otherwise hold for any message.
    assert(!pubkey.dbl().dbl().dbl().is_zero());

    // PRECONDITION of zkpassport sha512 v0.2.0 `sha512_var`: the storage after
    // the length must be zero; it hashes those bytes into the padding block.
    // `BoundedVec::new` zero-fills and `extend_*` copies only active bytes, so
    // `preimage` has a zero tail even if `message` does not.
    let mut preimage: BoundedVec<u8, 32 + 32 + MSG_MAX_LEN> = BoundedVec::new();
    preimage.extend_from_array(compress(sig_point));
    preimage.extend_from_array(compress(pubkey));
    preimage.extend_from_bounded_vec(message);

    let k = reduce_wide(sha512::sha512_var(preimage));

    // On the caller-proven subgroup, use the exact relation [S]B=R+[k]A.
    // The two scalar multiplications share a doubling ladder via an MSM.
    let basepoint = Ed25519::from(Ed25519Params::gen());
    // PRECONDITION: caller constrains A and R into the subgroup of order ell.
    // Upstream ScalarField<64> rejects the valid scalar zero; ScalarField<63>
    // with the reduction below covers every scalar below ell.
    let (s_point,s)=prime_subgroup_multiplier(basepoint,sig_scalar);
    let (k_point,k_scalar)=prime_subgroup_multiplier(pubkey.neg(),k);
    let lhs = Ed25519::msm([s_point,k_point], [s,k_scalar]);
    // Both points lie in the odd prime-order subgroup. Multiplication by8 is
    // injective there, so exact equality preserves the strict accepted domain.
    lhs == sig_point
}

/// Encode an Ed25519 point into its 32-byte compressed form (RFC 8032 5.1.2):
/// the little-endian y-coordinate with the low bit of x stored in the most
/// significant bit. Valid points have y < 2^255, so that bit is always free.
pub fn compress(point: Ed25519) -> [u8; 32] {
    let mut enc: [u8; 32] = point.y.to_le_bytes();
    let x_bytes: [u8; 32] = point.x.to_le_bytes();
    let x_sign = x_bytes[0] & 1;
    enc[31] = enc[31] | (x_sign << 7);
    enc
}

/// Reduce a 64-byte little-endian integer (the SHA-512 digest) modulo the
/// Ed25519 group order, returning it as a curve scalar.
///
/// Uses Horner's method over 32-bit words in the scalar field Fr
/// so the wide value is reduced as it is accumulated.
fn reduce_wide(bytes: [u8; 64]) -> Field {
    let base = Fr::from_limbs([0x100000000, 0, 0]); // 2^32
    let mut acc = Fr::zero();
    for i in 0..16 {
        let j = 15 - i; // most-significant 32-bit word first
        let word = (bytes[4 * j] as u128)
            + (bytes[4 * j + 1] as u128) * 0x100
            + (bytes[4 * j + 2] as u128) * 0x10000
            + (bytes[4 * j + 3] as u128) * 0x1000000;
        acc = acc * base + Fr::from_limbs([word, 0, 0]);
    }

    // acc is reduced mod ell (< 2^253), so it fits in a single field element.
    acc.validate_in_range();
    acc.validate_in_field();
    let limbs = acc.get_limbs();
    let p120: Field = 0x1000000000000000000000000000000; // 2^120
    let k_field =
        limbs[0] as Field + (limbs[1] as Field) * p120 + (limbs[2] as Field) * p120 * p120;
    k_field
}

/// This scalar representation is valid only on a point in the subgroup of
/// order ell. Each native ScalarField<63> input is proved below 2^252.
// Scalars x >= 2^252 are represented by (ell - x) on the negated point, so the
// coefficient is below 2^252. Every signed digit of the 63-slice decomposition
// lies in [-15, 15], so the represented integer lies in [-2^252, 2^252 - 1];
// its difference from the bounded coefficient has magnitude below 2^253, less
// than the BN254 scalar modulus, so the field reconstruction equality is an
// integer equality, given each slice below 16. edwards_bignum asserts that
// 4-bit bound and also uses the slices as 16-entry table indices, the pattern
// for which the pinned compiler can drop the RANGE and rely on the backend's
// memory bound (docs/zupass.md, backend premises).
// This does not justify ScalarField<64>.
pub fn prime_subgroup_multiplier(point:Ed25519,x:Field)->(Ed25519,ScalarField<63>){
    let ell:Field=7237005577332262213973186563042994240857116359379907606001950938285454250989;
    let limit:Field=0x1000000000000000000000000000000000000000000000000000000000000000;
    assert(x.lt(ell),"Ed25519 multiplier outside subgroup order");
    let upper=!x.lt(limit);
    let coefficient=if upper {ell-x}else{x};
    coefficient.assert_max_bit_size::<252>();
    (if upper {point.neg()}else{point},ScalarField::<63>::from(coefficient))
}

// Workspace tests exercise this modified prime-subgroup API, including all five
// upstream RFC8032 cases through the strict byte/subgroup wrapper.
