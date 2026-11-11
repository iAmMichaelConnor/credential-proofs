//! Context-free tests of the Sign in with Apple adapter. The token verification
//! runs in TXE in the login-link instance (`login-link/apple/src/test.nr`).
use crate::{APPLE_ISSUER, AppleIdToken, SCHEME_APPLE};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(modulus0: u128, audience_len: u32) -> AppleIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    AppleIdToken {
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
fn scheme_id_is_the_account_id() {
    assert_eq(<AppleIdToken as OidcProviderInput>::SCHEME, SCHEME_APPLE);
}

#[test]
fn issuer_constant_is_the_verified_issuer() {
    assert_eq(APPLE_ISSUER, poseidon2_hash_bytes("https://appleid.apple.com".as_bytes()));
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
