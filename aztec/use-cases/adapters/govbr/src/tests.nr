//! Context-free tests of the gov.br adapter. The token verification runs in
//! TXE in the login-link instance (`login-link/govbr/src/test.nr`).
use crate::{GOVBR_ISSUER, GOVBR_STAGING_ISSUER, GovbrIdToken, SCHEME_GOVBR};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(modulus0: u128, audience_len: u32) -> GovbrIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    GovbrIdToken {
        modulus_limbs,
        redc_params_limbs: [0; 18],
        staging: false,
        minimum_level: 2,
        audience: BoundedVec::from_parts([7; 128], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_govbr_account_id() {
    assert_eq(<GovbrIdToken as OidcProviderInput>::SCHEME, SCHEME_GOVBR);
}

#[test]
fn issuer_constants_are_the_verified_issuers() {
    assert_eq(GOVBR_ISSUER, poseidon2_hash_bytes("https://sso.acesso.gov.br/".as_bytes()));
    assert_eq(GOVBR_STAGING_ISSUER, poseidon2_hash_bytes("https://sso.staging.acesso.gov.br/".as_bytes()));
}

#[test]
fn issuer_pins_key_environment_level_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    assert(base != input(1, 5).issuer());
    let mut staging = input(1, 4);
    staging.staging = true;
    assert(base != staging.issuer());
    let mut lower = input(1, 4);
    lower.minimum_level = 1;
    assert(base != lower.issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test]
fn subject_scope_follows_the_environment_only() {
    let mut lower = input(1, 4);
    lower.minimum_level = 1;
    assert_eq(input(1, 4).issuer_name(), lower.issuer_name());
    let mut staging = input(1, 4);
    staging.staging = true;
    assert(input(1, 4).issuer_name() != staging.issuer_name());
}

#[test]
fn policy_hash_pins_the_subject() {
    let mut other = input(1, 4);
    other.subject = BoundedVec::from_parts([9; 256], 3);
    assert(input(1, 4).policy_hash() != other.policy_hash());
}
