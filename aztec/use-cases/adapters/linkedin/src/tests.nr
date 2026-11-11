//! Context-free tests of the LinkedIn adapter. The token verification runs
//! in TXE in the login-link instance (`login-link/linkedin/src/test.nr`).
use crate::{LINKEDIN_ISSUER, LinkedInIdToken, SCHEME_LINKEDIN};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::{nonce_of, OidcProviderInput};

fn input(modulus0: u128, audience_len: u32) -> LinkedInIdToken {
    let mut modulus_limbs = [0; 35];
    modulus_limbs[0] = modulus0;
    LinkedInIdToken {
        modulus_limbs,
        redc_params_limbs: [0; 35],
        audience: BoundedVec::from_parts([7; 256], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_linkedin_account_id() {
    assert_eq(<LinkedInIdToken as OidcProviderInput>::SCHEME, SCHEME_LINKEDIN);
}

#[test]
fn issuer_constant_is_the_verified_issuer() {
    assert_eq(LINKEDIN_ISSUER, poseidon2_hash_bytes("https://www.linkedin.com".as_bytes()));
}

#[test]
fn issuer_pins_key_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    let mut redc = input(1, 4);
    redc.redc_params_limbs[34] = 1;
    assert(base != redc.issuer());
    assert(base != input(1, 5).issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test(should_fail_with = "LinkedIn tokens carry no nonce")]
fn a_challenge_nonce_is_refused() {
    // OidcLink would pass the challenge as the nonce; the token has none.
    let _ = input(1, 4).verify(nonce_of(5), 100);
}
