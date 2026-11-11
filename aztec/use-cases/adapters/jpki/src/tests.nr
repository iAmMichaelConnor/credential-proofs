//! Context-free tests of the JPKI adapter. The chain, OCSP and card
//! signature checks run in TXE in the login-link jpki instance
//! (`login-link/jpki/src/test.nr`).
use crate::{card_key_id, jpki_pin, JpkiLogin, SCHEME_JPKI};
use uc_login_link::LoginLink;

#[test]
fn scheme_id_is_the_jpki_account_id() {
    assert_eq(<JpkiLogin as LoginLink>::SCHEME, SCHEME_JPKI);
}

#[test]
fn pin_separates_class_root_and_ocsp_age() {
    let root = [1; 32];
    let mut other_root = root;
    other_root[31] = 2;
    let base = jpki_pin(0, root, 300);
    assert(base != jpki_pin(1, root, 300));
    assert(base != jpki_pin(0, other_root, 300));
    assert(base != jpki_pin(0, root, 301));
}

#[test]
fn card_key_id_reads_both_halves() {
    let mut a = [0; 32];
    let mut b = [0; 32];
    a[0] = 1;
    b[31] = 1;
    assert(card_key_id(a) != card_key_id(b));
}
