//! Full verification (signature, key and layout) on generated vectors.
//! Expected values are written out by hand or computed by the host generator
//! with independent code (Date.UTC), never read back from this circuit.

use crate::{
    IDENTITY_DOMAIN, issuer_key_hash, nullifier_from_identity, SecureQr, SecureQrInput,
    UPSTREAM_TEST_ISSUER_KEY_HASH, vectors, verify,
};
use poseidon::poseidon2::Poseidon2;

global SEED: Field = 12345678;
/// Upstream productionPublicKeyHash (packages/core/src/constants.ts at 4dad918).
global UIDAI_2021_KEY_HASH: Field =
    18063425702624337643644061197836918910810808173893535653269228433734128853484;

fn upstream_qr() -> SecureQr<vectors::N> {
    verify(vectors::upstream(), UPSTREAM_TEST_ISSUER_KEY_HASH)
}

fn synthetic(input: SecureQrInput<vectors::N>) -> SecureQr<vectors::N> {
    verify(input, vectors::SYNTHETIC_ISSUER_KEY_HASH)
}

/// Check everything except the RSA relation, then run full verification.
/// The pinned noir_rsa fails these cases on an unlabelled assert, so the
/// test first shows that the key hash and the layout accept the input; only
/// the signature relation is left to fail.
fn verify_expecting_signature_failure(input: SecureQrInput<vectors::N>, key_hash: Field) {
    assert_eq(issuer_key_hash(input.modulus), key_hash);
    let _ = crate::layout::parse(input.signed_data, input.delimiters, key_hash);
    let _ = verify(input, key_hash);
}

/// Big-endian pack of one 31-byte chunk, zero-filled on the right.
fn chunk_bytes<let K: u32>(bytes: [u8; K], index: u32) -> Field {
    let mut value = 0;
    for i in 0..31 {
        let k = index * 31 + i;
        value = value * 256 + if k < K { bytes[k] as Field } else { 0 };
    }
    value
}

#[test]
fn key_hashes_match_upstream_constants() {
    assert_eq(issuer_key_hash(vectors::upstream().modulus), UPSTREAM_TEST_ISSUER_KEY_HASH);
    assert_eq(issuer_key_hash(vectors::UIDAI_2021_MODULUS), UIDAI_2021_KEY_HASH);
}

#[test]
fn synthetic_issuer_key_hash_is_recorded() {
    assert_eq(issuer_key_hash(vectors::s2032().modulus), vectors::SYNTHETIC_ISSUER_KEY_HASH);
}

#[test]
fn upstream_public_test_qr_verifies() {
    let qr = upstream_qr();
    assert_eq(qr.issuer_key_hash(), UPSTREAM_TEST_ISSUER_KEY_HASH);
    // Reference id 2697 20240420014552930: 2024-04-20 01:45:52 IST.
    assert_eq(qr.issued_at(), 1713557752);
    assert_eq(qr.issued_at(), vectors::UPSTREAM_ISSUED_AT);
    assert_eq(qr.gender(), 77);
    assert_eq(qr.pincode(), 110051);
    let state = qr.state();
    assert_eq(state.len(), 5);
    let delhi = "Delhi".as_bytes();
    for i in 0..5 {
        assert_eq(state.get(i), delhi[i]);
    }
    // Born 01-01-1984, issued 2024-04-20: 40 whole years.
    assert(qr.age_at_least(18));
    assert(qr.age_at_least(40));
    assert(!qr.age_at_least(41));
}

#[test]
fn identity_commitment_follows_the_documented_derivation() {
    let qr = upstream_qr();
    let name = chunk_bytes("Sumit Kumar".as_bytes(), 0);
    let expected = Poseidon2::hash(
        [IDENTITY_DOMAIN, 2697, 1984, 1, 1, 11, name, 0, 0, 0, 0],
        11,
    );
    assert_eq(qr.identity_commitment(), expected);
    assert_eq(qr.nullifier(SEED), nullifier_from_identity(expected, SEED));
    assert(qr.nullifier(SEED) != qr.nullifier(SEED + 1));
}

#[test(should_fail_with = "Wrong Aadhaar issuer key")]
fn rejects_an_unexpected_issuer_key() {
    let _ = verify(vectors::upstream(), UIDAI_2021_KEY_HASH);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
fn rejects_a_signature_from_another_key() {
    let mut input = vectors::upstream();
    let other = vectors::s2032();
    input.modulus = other.modulus;
    input.redc = other.redc;
    verify_expecting_signature_failure(input, vectors::SYNTHETIC_ISSUER_KEY_HASH);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
fn rejects_a_changed_signature() {
    let mut input = vectors::upstream();
    input.signature[0] += 1;
    verify_expecting_signature_failure(input, UPSTREAM_TEST_ISSUER_KEY_HASH);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
fn rejects_an_altered_birth_year() {
    let mut input = vectors::upstream();
    let mut storage = input.signed_data.storage();
    // DOB 01-01-1984 sits at bytes 39..48; make it 1983.
    storage[48] = 51;
    input.signed_data = BoundedVec::from_parts(storage, input.signed_data.len());
    verify_expecting_signature_failure(input, UPSTREAM_TEST_ISSUER_KEY_HASH);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
fn rejects_a_truncated_message() {
    let mut input = vectors::upstream();
    let length = input.signed_data.len() - 1;
    let mut storage = input.signed_data.storage();
    storage[length] = 0;
    input.signed_data = BoundedVec::from_parts(storage, length);
    verify_expecting_signature_failure(input, UPSTREAM_TEST_ISSUER_KEY_HASH);
}

#[test]
fn year_2032_is_exact() {
    // Upstream gives 1961649000 (one day early) for 2032-03-01 12:00 IST.
    let qr = synthetic(vectors::s2032());
    assert_eq(qr.issued_at(), 1961735400);
    assert_eq(qr.issued_at(), vectors::S2032_ISSUED_AT);
}

#[test]
fn nullifier_survives_photo_update_reissue_and_key_change() {
    // Same person, new photo, new issuance time, different signing key.
    let first = synthetic(vectors::s2032()).nullifier(SEED);
    let reissued = synthetic(vectors::reissue());
    assert_eq(reissued.issued_at(), vectors::REISSUE_ISSUED_AT);
    assert_eq(reissued.nullifier(SEED), first);
    assert_eq(upstream_qr().nullifier(SEED), first);
}

#[test]
fn a_different_name_is_a_different_identity() {
    let renamed = synthetic(vectors::renamed());
    assert(renamed.nullifier(SEED) != synthetic(vectors::s2032()).nullifier(SEED));
}

#[test]
fn maximal_supported_input_verifies() {
    let input = vectors::maximal();
    assert_eq(input.signed_data.len(), vectors::N);
    let qr = synthetic(input);
    assert_eq(qr.issued_at(), 1646072999);
    assert_eq(qr.issued_at(), vectors::MAXIMAL_ISSUED_AT);
    assert_eq(qr.gender(), 70);
    assert_eq(qr.pincode(), 560001);
    assert_eq(qr.state().len(), 64);
    // Born 29-02-2004, issued 2022-02-28 23:59:59 IST: the 18th birthday is
    // 1 March 2022.
    assert(!qr.age_at_least(18));
    assert(qr.age_at_least(17));
    let name = [65; 155];
    let expected = Poseidon2::hash(
        [
            IDENTITY_DOMAIN,
            2697,
            2004,
            2,
            29,
            155,
            chunk_bytes(name, 0),
            chunk_bytes(name, 1),
            chunk_bytes(name, 2),
            chunk_bytes(name, 3),
            chunk_bytes(name, 4),
        ],
        11,
    );
    assert_eq(qr.identity_commitment(), expected);
}

#[test]
fn a_signed_name_longer_than_supported_still_verifies_attributes() {
    // 156-byte name. Age, gender, PIN code and state gating do not read the name.
    let qr = synthetic(vectors::long_name());
    assert_eq(qr.issued_at(), vectors::LONG_NAME_ISSUED_AT);
    assert(qr.age_at_least(18));
    assert_eq(qr.gender(), 77);
    assert_eq(qr.pincode(), 110051);
    assert_eq(qr.state().len(), 5);
}

#[test(should_fail_with = "Name exceeds supported length")]
fn rejects_a_name_longer_than_supported() {
    let _ = synthetic(vectors::long_name()).nullifier(SEED);
}

// A signed length above N cannot be built in a Noir test, because
// BoundedVec::from_parts asserts len <= N. The prover can still set it in the
// ABI. The example fixture ProverSignedLengthAboveCapacity.toml covers that case.

#[test]
fn signature_failure_helper_controls_pass_on_valid_input() {
    // The same pre-checks and verification succeed when nothing is changed.
    verify_expecting_signature_failure(vectors::upstream(), UPSTREAM_TEST_ISSUER_KEY_HASH);
}
