//! Context-free tests of the OIDC family helpers. The wrappers run in TXE in
//! `testing/family_oidc_tests` and in the login-link Google instance.
use crate::{bounded_bytes_hash, issuer_pin, nonce_of, p256_key_hash, rsa4096_key_hash, rsa_key_hash, subject_id};

#[test]
fn nonce_is_lowercase_hex_of_the_value() {
    let nonce = nonce_of(0xab01);
    assert_eq(nonce.len(), 64);
    assert_eq(nonce.get(61), "b".as_bytes()[0]);
    assert_eq(nonce.get(63), "1".as_bytes()[0]);
    assert_eq(nonce.get(0), "0".as_bytes()[0]);
    assert_eq(nonce.storage(), uc_trust::field_hex(0xab01));
}

#[test]
fn bytes_hash_ignores_storage_after_len() {
    let clean: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 0, 0, 0, 0, 0], 3);
    let dirty: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 9, 9, 9, 9, 9], 3);
    assert_eq(bounded_bytes_hash(clean), bounded_bytes_hash(dirty));
}

#[test]
fn bytes_hash_commits_to_length() {
    let short: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 0, 0, 0, 0, 0, 0], 2);
    let long: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 0, 0, 0, 0, 0, 0], 3);
    assert(bounded_bytes_hash(short) != bounded_bytes_hash(long));
}

#[test]
fn issuer_pin_separates_key_issuer_and_audience() {
    let pin = issuer_pin(1, 2, 3);
    assert(pin != issuer_pin(4, 2, 3));
    assert(pin != issuer_pin(1, 4, 3));
    assert(pin != issuer_pin(1, 2, 4));
}

#[test]
fn subject_id_is_scoped_by_issuer_and_differs_from_the_pin() {
    assert(subject_id(2, 5) != subject_id(3, 5));
    assert(subject_id(2, 5) != subject_id(2, 6));
    assert(subject_id(1, 2) != issuer_pin(1, 2, 0));
}

#[test]
fn rsa_key_hashes_cover_modulus_and_barrett_parameters() {
    let key2048 = rsa_key_hash([1; 18], [2; 18]);
    assert(key2048 != rsa_key_hash([1; 18], [3; 18]));
    let mut modulus = [1; 18];
    modulus[17] = 4;
    assert(key2048 != rsa_key_hash(modulus, [2; 18]));
    let key4096 = rsa4096_key_hash([1; 35], [2; 35]);
    assert(key4096 != rsa4096_key_hash([1; 35], [3; 35]));
    let mut modulus = [1; 35];
    modulus[34] = 4;
    assert(key4096 != rsa4096_key_hash(modulus, [2; 35]));
}

#[test]
fn p256_key_hash_separates_coordinates() {
    let mut x = [0; 32];
    x[0] = 1;
    let y = [0; 32];
    assert(p256_key_hash(x, y) != p256_key_hash(y, x));
}
