//! Context-free tests of the FranceConnect+ adapter. The token verification
//! runs in TXE in the login-link instance (`login-link/franceconnect/src/test.nr`).
use crate::{FRANCECONNECT_INTEGRATION_ISSUER, FRANCECONNECT_ISSUER, FranceConnectIdToken, SCHEME_FRANCECONNECT};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(x0: u8, audience_len: u32) -> FranceConnectIdToken {
    let mut public_key_x = [0; 32];
    public_key_x[0] = x0;
    FranceConnectIdToken {
        public_key_x,
        public_key_y: [0; 32],
        integration: false,
        minimum_acr: 2,
        audience: BoundedVec::from_parts([7; 128], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_franceconnect_account_id() {
    assert_eq(<FranceConnectIdToken as OidcProviderInput>::SCHEME, SCHEME_FRANCECONNECT);
}

#[test]
fn issuer_constants_are_the_verified_issuers() {
    assert_eq(FRANCECONNECT_ISSUER, poseidon2_hash_bytes("https://auth.franceconnect.gouv.fr/api/v2".as_bytes()));
    assert_eq(
        FRANCECONNECT_INTEGRATION_ISSUER,
        poseidon2_hash_bytes(
            "https://auth.integ01.dev-franceconnect.fr/api/v2".as_bytes(),
        ),
    );
}

#[test]
fn issuer_pins_key_environment_level_and_audience() {
    let base = input(1, 4).issuer();
    assert(base != input(2, 4).issuer());
    assert(base != input(1, 5).issuer());
    let mut integration = input(1, 4);
    integration.integration = true;
    assert(base != integration.issuer());
    let mut higher = input(1, 4);
    higher.minimum_acr = 3;
    assert(base != higher.issuer());
    assert_eq(base, input(1, 4).issuer());
}

#[test]
fn subject_scope_follows_the_environment_only() {
    let mut higher = input(1, 4);
    higher.minimum_acr = 3;
    assert_eq(input(1, 4).issuer_name(), higher.issuer_name());
    let mut integration = input(1, 4);
    integration.integration = true;
    assert(input(1, 4).issuer_name() != integration.issuer_name());
}

#[test]
fn policy_hash_pins_the_subject() {
    let mut other = input(1, 4);
    other.subject = BoundedVec::from_parts([9; 256], 3);
    assert(input(1, 4).policy_hash() != other.policy_hash());
}

#[test]
fn assurance_wrapper_preserves_trust_and_subject_policy() {
    let raw = input(1, 2);
    let wrapped = crate::FranceConnectAssuranceToken { token: raw };
    assert_eq(wrapped.issuer(), raw.issuer());
    assert_eq(wrapped.policy_hash(), raw.policy_hash());
    assert_eq(<crate::FranceConnectAssuranceToken as OidcProviderInput>::SCHEME, SCHEME_FRANCECONNECT);
}
