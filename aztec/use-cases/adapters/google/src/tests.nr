//! Context-free tests of the Google adapter. The token verification runs in
//! TXE in the login-link Google instance (`login-link/google/src/test.nr`).
use crate::{GOOGLE_ISSUER, GoogleIdToken, SCHEME_GOOGLE};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(modulus0: u128, audience_len: u32) -> GoogleIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    GoogleIdToken {
        modulus_limbs,
        redc_params_limbs: [0; 18],
        audience: BoundedVec::from_parts([7; 128], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_google_account_id() {
    assert_eq(<GoogleIdToken as OidcProviderInput>::SCHEME, SCHEME_GOOGLE);
}

#[test]
fn issuer_constant_is_the_canonical_issuer() {
    assert_eq(GOOGLE_ISSUER, poseidon2_hash_bytes("https://accounts.google.com".as_bytes()));
}

#[test]
fn issuer_pins_key_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    assert(base != input(1, 5).issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test]
fn policy_hash_pins_the_subject() {
    let mut other = input(1, 4);
    other.subject = BoundedVec::from_parts([9; 256], 3);
    assert(input(1, 4).policy_hash() != other.policy_hash());
}
