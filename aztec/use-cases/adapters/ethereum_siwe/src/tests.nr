//! Context-free tests of the SIWE adapter. The message and signature
//! verification runs in TXE in the login-link ethereum_siwe instance
//! (`login-link/ethereum_siwe/src/test.nr`).
use crate::{address_id, SCHEME_ETHEREUM_SIWE, siwe_pin, SiweLogin};
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
fn scheme_id_is_the_siwe_account_id() {
    assert_eq(<SiweLogin as LoginLink>::SCHEME, SCHEME_ETHEREUM_SIWE);
}

#[test]
fn siwe_pin_separates_domain_uri_and_chain() {
    let domain = padded("example.com");
    let uri = padded("https://example.com/login");
    let base = siwe_pin(domain, 11, uri, 25, 1);
    assert(base != siwe_pin(padded("example.org"), 11, uri, 25, 1));
    assert(base != siwe_pin(domain, 11, padded("https://example.com/other"), 25, 1));
    assert(base != siwe_pin(domain, 11, uri, 25, 10));
    assert(base != siwe_pin(domain, 10, uri, 25, 1));
}

#[test]
fn address_id_reads_all_twenty_bytes() {
    let mut a = [0; 20];
    let mut b = [0; 20];
    a[0] = 1;
    b[19] = 1;
    assert(address_id(a) != address_id(b));
    assert(address_id(a) != address_id([0; 20]));
}
