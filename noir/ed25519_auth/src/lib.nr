//! Strict, byte-bound Ed25519 over the workspace-compatible BigNum foundation.
//! Coordinates are supplied hints, never independent public keys or signatures.
//!
//! `verify` accepts the strict prime-order-subgroup profile: canonical
//! compressed A and R, canonical 0 <= S < ell, nonidentity A, and A and R in the
//! subgroup of order ell. It is narrower than cofactored variants that accept
//! mixed-torsion encodings. A valid identity R and S = 0 stay accepted when the
//! full equation holds; do not replace this with blanket nonzero checks. The
//! caller selects and authenticates the issuer key. The full-field
//! `ScalarField<64>` path is bypassed (it rejects the valid scalar zero); see
//! `prime_subgroup_multiplier` in `vendor/noir-ed25519` for the 63-slice bound.
//! The Git dependency `edwards_bignum` v0.1.0-alpha.4 is labelled unaudited
//! upstream. Host hints come from `packages/credential-proofs-inputs/src/ed25519.ts`;
//! neither hint generation nor host verification replaces this relation.
use bignum::{BigNum, ED25519_Fq as Fq};
use edwards_bignum::{CurveTrait, ScalarField};
use edwards_bignum::ed25519::Ed25519;

global ELL: Field = 7237005577332262213973186563042994240857116359379907606001950938285454250989;

pub struct PointHint {
    pub x_limbs: [u128; 3],
    pub y_limbs: [u128; 3],
}

/// Constrain each coordinate to canonical limbs of an integer in [0, p).
/// BigNum validate_in_field accepts val == p; with in-range limbs the limb
/// vector of p is unique, so excluding it gives the strict bound. compress()
/// reads the x sign bit from the raw limbs, so x = p (an alias of x = 0) would
/// otherwise bind the non-RFC 8032 identity encoding 01 00..00 80.
fn point_from_hint(hint: PointHint) -> Ed25519 {
    let x = Fq::from_limbs(hint.x_limbs);
    let y = Fq::from_limbs(hint.y_limbs);
    let p = Fq::modulus().get_limbs();
    x.validate_in_range();
    x.validate_in_field();
    assert(hint.x_limbs != p, "Ed25519 point hint is not canonical");
    y.validate_in_range();
    y.validate_in_field();
    assert(hint.y_limbs != p, "Ed25519 point hint is not canonical");
    let point = Ed25519::from((x, y));
    point.assert_is_on_curve();
    point
}

/// Accept canonical compressed points in the prime-order subgroup, with a
/// nonidentity issuer key. Scalar S must be canonical in [0,ell); S=0 and R=O
/// remain valid exceptional values if their complete signature equation holds.
/// The upstream cofactored equation is exact on these constrained subgroups.
pub fn verify<let N: u32>(
    public_key: [u8; 32],
    signature: [u8; 64],
    message: BoundedVec<u8, N>,
    public_hint: PointHint,
    signature_hint: PointHint,
) {
    assert(message.len() <= N, "Ed25519 message exceeds capacity");
    let key = point_from_hint(public_hint);
    let r = point_from_hint(signature_hint);
    let key_bytes = ed25519::compress(key);
    let r_bytes = ed25519::compress(r);
    for i in 0..32 {
        assert(key_bytes[i] == public_key[i], "Ed25519 public point hint does not match key bytes");
        assert(
            r_bytes[i] == signature[i],
            "Ed25519 signature point hint does not match signature bytes",
        );
    }
    assert(!key.is_zero(), "Ed25519 issuer key is identity");
    assert(
        (key.mul(ScalarField::<63>::from((ELL - 1) / 2)).dbl() + key).is_zero(),
        "Ed25519 issuer key outside prime subgroup",
    );
    assert(
        (r.mul(ScalarField::<63>::from((ELL - 1) / 2)).dbl() + r).is_zero(),
        "Ed25519 signature point outside prime subgroup",
    );
    let order: [u8; 32] = [
        237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
    ];
    let mut equal = true;
    let mut less = false;
    for j in 0..32 {
        let i = 31 - j;
        less = less | (equal & (signature[32 + i] < order[i]));
        equal = equal & (signature[32 + i] == order[i]);
    }
    assert(less, "Ed25519 scalar is not canonical");
    let mut scalar: Field = 0;
    for j in 0..32 {
        scalar = scalar * 256 + signature[63 - j] as Field;
    }
    assert(
        ed25519::ed25519_verify_prime_subgroup(key, scalar, r, message),
        "Ed25519 signature verification failed",
    );
}

mod tests;
pub mod benchmarks;
