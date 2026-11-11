//! Context-free tests of the LINE adapter. The token verification runs in
//! TXE in the login-link instance (`login-link/line/src/test.nr`).
use crate::{LINE_ISSUER, LineIdToken, SCHEME_LINE};
use aztec::protocol::hash::poseidon2_hash_bytes;
use uc_family_oidc::OidcProviderInput;

fn input(x0: u8, audience_len: u32) -> LineIdToken {
    let mut public_key_x = [0; 32];
    public_key_x[0] = x0;
    LineIdToken {
        public_key_x,
        public_key_y: [0; 32],
        audience: BoundedVec::from_parts([49; 32], audience_len),
        subject: BoundedVec::from_parts([8; 256], 3),
        header_b64: BoundedVec::new(),
        payload_b64: BoundedVec::new(),
        signature_b64: BoundedVec::new(),
    }
}

#[test]
fn scheme_id_is_the_line_account_id() {
    assert_eq(<LineIdToken as OidcProviderInput>::SCHEME, SCHEME_LINE);
}

#[test]
fn issuer_constant_is_the_verified_issuer() {
    assert_eq(LINE_ISSUER, poseidon2_hash_bytes("https://access.line.me".as_bytes()));
}

#[test]
fn issuer_pins_key_and_channel() {
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
