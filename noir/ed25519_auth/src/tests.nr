use crate::{PointHint, verify};
use bignum::{BigNum, ED25519_Fq as Fq};
use edwards_bignum::{CurveTrait, ScalarField};
use edwards_bignum::ed25519::Ed25519;
use std::ops::Neg;
fn fixture() -> ([u8; 32], [u8; 64], PointHint, PointHint) {
    (
        [
            25, 127, 107, 35, 225, 108, 133, 50, 198, 171, 200, 56, 250, 205, 94, 167, 137, 190, 12,
            118, 178, 146, 3, 52, 3, 155, 250, 139, 61, 54, 141, 97,
        ],
        [
            48, 187, 73, 88, 64, 57, 255, 169, 164, 81, 137, 227, 222, 200, 82, 167, 38, 112, 25,
            242, 230, 216, 129, 92, 16, 241, 62, 183, 233, 150, 175, 31, 145, 103, 183, 70, 101,
            242, 231, 176, 14, 96, 180, 71, 148, 88, 11, 32, 154, 65, 211, 33, 187, 62, 172, 209,
            112, 147, 64, 168, 201, 202, 235, 13,
        ],
        PointHint {
            x_limbs: [
                454255119195748667115557750742425420,
                273434672773717476713123556025632099,
                28191,
            ],
            y_limbs: [
                492253623285407850285756802816245529,
                281632347619944010543572580625713575,
                24973,
            ],
        },
        PointHint {
            x_limbs: [
                1286058627590472602477868662925256318,
                298843475926927819531827099804856074,
                31071,
            ],
            y_limbs: [
                429842483391769982240483703092001584,
                783584848451114089633316518463809191,
                8111,
            ],
        },
    )
}
#[test]
fn valid() {
    let (mut a, mut s, mut ah, mut rh) = fixture();
    verify::<18>(
        a,
        s,
        BoundedVec::from_array("PhilSys local test".as_bytes()),
        ah,
        rh,
    );
}
#[test(should_fail_with = "Ed25519 signature verification failed")]
fn reject_binding_changed_message() {
    let (mut a, mut s, mut ah, mut rh) = fixture();
    verify::<18>(
        a,
        s,
        BoundedVec::from_array("PhilSys local tesU".as_bytes()),
        ah,
        rh,
    );
}
#[test(should_fail_with = "Ed25519 scalar is not canonical")]
fn scalar_alias() {
    let (mut a, mut s, mut ah, mut rh) = fixture();
    s = [
        48, 187, 73, 88, 64, 57, 255, 169, 164, 81, 137, 227, 222, 200, 82, 167, 38, 112, 25, 242,
        230, 216, 129, 92, 16, 241, 62, 183, 233, 150, 175, 31, 126, 59, 173, 163, 127, 85, 250, 8,
        229, 252, 171, 234, 114, 82, 234, 52, 154, 65, 211, 33, 187, 62, 172, 209, 112, 147, 64,
        168, 201, 202, 235, 29,
    ];
    verify::<18>(
        a,
        s,
        BoundedVec::from_array("PhilSys local test".as_bytes()),
        ah,
        rh,
    );
}
// Bare: the rejection is the message-less assert at noir-edwards-bignum v0.1.0-alpha.4 src/lib.nr:166.
#[test(should_fail)]
fn reject_point_offcurve_hint() {
    let (mut a, mut s, mut ah, mut rh) = fixture();
    ah = PointHint { x_limbs: [0, 0, 0], y_limbs: [0, 0, 0] };
    verify::<18>(
        a,
        s,
        BoundedVec::from_array("PhilSys local test".as_bytes()),
        ah,
        rh,
    );
}
#[test]
fn scalar63_boundaries() {
    let values: [Field; 3] =
        [0, 1, 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff];
    for i in 0..3 {
        let scalar = edwards_bignum::ScalarField::<63>::from(values[i]);
        let actual: Field = scalar.into();
        assert(actual == values[i]);
    }
}
#[test]
fn scalar63_zero_multiplication() {
    assert(Ed25519::one().mul(ScalarField::<63>::from(0)).is_zero());
}
#[test]
fn signed_scalar_boundaries() {
    let mut independently_computed_limit: Field = 1;
    for _ in 0..252 {
        independently_computed_limit *= 2;
    }
    assert(
        independently_computed_limit
            == 0x1000000000000000000000000000000000000000000000000000000000000000,
    );
    let limit: Field = 0x1000000000000000000000000000000000000000000000000000000000000000;
    let ell: Field = 7237005577332262213973186563042994240857116359379907606001950938285454250989;
    let values: [Field; 5] = [0, limit - 1, limit, limit + 1, ell - 1];
    let p = Ed25519::one();
    for i in 0..5 {
        let (point, scalar) = ed25519::prime_subgroup_multiplier(p, values[i]);
        let coefficient: Field = scalar.into();
        assert(coefficient == if i < 2 { values[i] } else { ell - values[i] });
        assert(point == if i < 2 { p } else { p.neg() });
    }
}
