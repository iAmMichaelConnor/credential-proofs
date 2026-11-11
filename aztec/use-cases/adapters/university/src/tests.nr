//! Context-free tests of the university (CILogon) adapter. The token
//! verification runs in TXE in the login-link instance
//! (`login-link/university/src/test.nr`).
use crate::{affiliation_attribute, CILOGON_ISSUER, SCHEME_UNIVERSITY, UniversityAffiliationToken, UniversityIdToken};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(modulus0: u128, audience_len: u32) -> UniversityIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    UniversityIdToken {
        modulus_limbs,
        redc_params_limbs: [0; 18],
        institutional_idp: BoundedVec::from_parts([6; 256], 5),
        audience: BoundedVec::from_parts([7; 128], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_university_account_id() {
    assert_eq(<UniversityIdToken as OidcProviderInput>::SCHEME, SCHEME_UNIVERSITY);
}

#[test]
fn issuer_constant_is_the_cilogon_issuer() {
    assert_eq(CILOGON_ISSUER, poseidon2_hash_bytes("https://cilogon.org".as_bytes()));
}

#[test]
fn issuer_pins_key_campus_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    assert(base != input(1, 5).issuer());
    let mut campus = input(1, 4);
    campus.institutional_idp = BoundedVec::from_parts([6; 256], 6);
    assert(base != campus.issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test]
fn policy_hash_pins_the_subject() {
    let mut other = input(1, 4);
    other.subject = BoundedVec::from_parts([9; 256], 3);
    assert(input(1, 4).policy_hash() != other.policy_hash());
}

#[test]
fn affiliation_input_keeps_the_token_pins() {
    // The affiliation is the reported value, not part of the issuer pin or
    // the policy; the scheme id is the university id.
    let entry = BoundedVec::from_parts([5; 128], 4);
    let wrapped = UniversityAffiliationToken { token: input(1, 4), affiliation: entry };
    assert_eq(<UniversityAffiliationToken as OidcProviderInput>::SCHEME, SCHEME_UNIVERSITY);
    assert_eq(wrapped.policy_hash(), input(1, 4).policy_hash());
    let other = UniversityAffiliationToken { token: input(1, 4), affiliation: BoundedVec::from_parts([5; 128], 5) };
    assert_eq(other.policy_hash(), wrapped.policy_hash());
}

#[test]
fn affiliation_attribute_reads_only_the_entry() {
    // Bytes after the length are ignored; the length counts.
    let mut storage = [0; 128];
    let text = "student@example.edu".as_bytes();
    for i in 0..19 {
        storage[i] = text[i];
    }
    let entry = BoundedVec::from_parts(storage, 19);
    storage[100] = 1;
    assert_eq(affiliation_attribute(entry), affiliation_attribute(BoundedVec::from_parts(storage, 19)));
    assert(affiliation_attribute(entry) != affiliation_attribute(BoundedVec::from_parts(storage, 18)));
}
