//! Context-free tests of the Facebook Limited Login adapter. The token verification
//! runs in TXE in the login-link instance (`login-link/facebook/src/test.nr`).
use crate::{FACEBOOK_ISSUER, FacebookIdToken, SCHEME_FACEBOOK};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(modulus0: u128, audience_len: u32) -> FacebookIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    FacebookIdToken {
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
    assert_eq(<FacebookIdToken as OidcProviderInput>::SCHEME, SCHEME_FACEBOOK);
}

#[test]
fn issuer_constant_is_the_verified_issuer() {
    assert_eq(FACEBOOK_ISSUER, poseidon2_hash_bytes("https://www.facebook.com".as_bytes()));
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
