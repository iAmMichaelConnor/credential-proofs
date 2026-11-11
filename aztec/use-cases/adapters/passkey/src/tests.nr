//! Context-free tests of the passkey adapter. The assertion verification
//! runs in TXE in the login-link passkey instance
//! (`login-link/passkey/src/test.nr`).
use crate::{key_id, PasskeyLogin, rp_pin, SCHEME_PASSKEY};
use uc_login_link::LoginLink;

fn padded<let N: u32, let M: u32>(text: str<M>) -> [u8; N] {
    let bytes = text.as_bytes();
    let mut out = [0; N];
    for i in 0..M {
        out[i] = bytes[i];
    }
    out
}

#[test]
fn scheme_id_is_the_passkey_account_id() {
    assert_eq(<PasskeyLogin as LoginLink>::SCHEME, SCHEME_PASSKEY);
}

#[test]
fn rp_pin_separates_rp_id_origin_and_user_verification() {
    let rp = padded("example.com");
    let other_rp = padded("example.org");
    let origin = padded("https://example.com");
    let other_origin = padded("https://login.example.com");
    let base = rp_pin(rp, 11, origin, 19, true);
    assert(base != rp_pin(other_rp, 11, origin, 19, true));
    assert(base != rp_pin(rp, 11, other_origin, 25, true));
    assert(base != rp_pin(rp, 11, origin, 19, false));
    assert_eq(base, rp_pin(rp, 11, origin, 19, true));
}

#[test]
fn key_id_separates_coordinates() {
    let mut x = [0; 32];
    let y = [0; 32];
    x[31] = 1;
    assert(key_id(x, y) != key_id(y, x));
    assert(key_id(x, y) != key_id(y, y));
}
