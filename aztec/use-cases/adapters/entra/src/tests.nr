//! Context-free tests of the Entra adapter. The token verification runs in
//! TXE in the login-link instance (`login-link/entra/src/test.nr`).
use crate::{EntraIdToken, SCHEME_ENTRA, tenant_attribute};
use uc_family_oidc::{bounded_bytes_hash, OidcProviderInput};

global TENANT: [u8; 36] = [
    49, 50, 51, 52, 53, 54, 55, 56, 45, 49, 50, 51, 52, 45, 49, 50, 51, 52, 45, 49, 50, 51, 52, 45, 49, 50, 51, 52, 53,
    54, 55, 56, 57, 97, 98, 99,
];

fn input(modulus0: u128, audience_len: u32) -> EntraIdToken {
    let mut modulus_limbs = [0; 18];
    modulus_limbs[0] = modulus0;
    EntraIdToken {
        modulus_limbs,
        redc_params_limbs: [0; 18],
        tenant: TENANT,
        audience: BoundedVec::from_parts([7; 128], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_entra_account_id() {
    assert_eq(<EntraIdToken as OidcProviderInput>::SCHEME, SCHEME_ENTRA);
}

#[test]
fn issuer_name_is_the_tenant_issuer() {
    let expected: BoundedVec<u8, 256> = BoundedVec::from_array(
        "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0".as_bytes(),
    );
    assert_eq(input(1, 4).issuer_name(), bounded_bytes_hash(expected));
}

#[test]
fn issuer_pins_key_tenant_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    assert(base != input(1, 5).issuer());
    let mut other = input(1, 4);
    other.tenant[35] = 100;
    assert(base != other.issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test(should_fail_with = "tenant must be a canonical GUID")]
fn noncanonical_tenant_rejected() {
    let mut other = input(1, 4);
    other.tenant[35] = 67; // 'C': upper case is not canonical
    let _ = other.issuer();
}

#[test]
fn policy_hash_pins_the_subject() {
    let mut other = input(1, 4);
    other.subject = BoundedVec::from_parts([9; 256], 3);
    assert(input(1, 4).policy_hash() != other.policy_hash());
}

#[test]
fn tenant_attribute_is_the_issuer_name() {
    // The reported attribute is the hash already in the pinned issuer.
    assert_eq(tenant_attribute(TENANT), input(1, 4).issuer_name());
    let mut other = input(1, 4);
    other.tenant[35] = 100;
    assert(tenant_attribute(other.tenant) != tenant_attribute(TENANT));
}
