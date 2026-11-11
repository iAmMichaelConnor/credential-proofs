// Plain unit tests of the adapter's pure helpers; the POD tests are TXE tests
// in attribute-gating/zupass_pod/src/test.nr.
use crate::{holder_id, holder_issuer_pin, issuer_pin, MAX_ENTRY_VALUE, pod_id, SCHEME_ZUPASS, ZupassHolderLogin};
use uc_login_link::LoginLink;

#[test]
fn issuer_pin_covers_the_entry_name() {
    assert(issuer_pin(1, 2, 3) != issuer_pin(1, 2, 4));
    assert(issuer_pin(1, 2, 3) != issuer_pin(2, 1, 3));
}

#[test]
fn pod_id_separates_issuers() {
    assert(pod_id(1, 2, 3) != pod_id(1, 3, 3));
}

#[test]
fn maximum_value_is_the_largest_int64() {
    assert_eq(MAX_ENTRY_VALUE + 1, 2.pow_32(63));
}

#[test]
fn holder_login_scheme_id_is_the_zupass_account_id() {
    assert_eq(<ZupassHolderLogin as LoginLink>::SCHEME, SCHEME_ZUPASS);
}

#[test]
fn holder_issuer_pin_covers_the_holder_entry_and_differs_from_the_pod_pin() {
    assert(holder_issuer_pin(1, 2, 3) != holder_issuer_pin(1, 2, 4));
    assert(holder_issuer_pin(1, 2, 3) != holder_issuer_pin(2, 1, 3));
    assert(holder_issuer_pin(1, 2, 3) != issuer_pin(1, 2, 3));
}

#[test]
fn holder_id_separates_keys() {
    assert(holder_id(1, 2) != holder_id(2, 1));
}

#[test]
fn holder_entry_pin_covers_both_names_and_issuer() {
    let pin = crate::holder_entry_issuer_pin(1, 2, 3, 4);
    assert(pin != crate::holder_entry_issuer_pin(1, 2, 5, 4));
    assert(pin != crate::holder_entry_issuer_pin(1, 2, 3, 5));
    assert(pin != crate::holder_entry_issuer_pin(2, 1, 3, 4));
    assert(pin != holder_issuer_pin(1, 2, 4));
    assert(pin != issuer_pin(1, 2, 3));
}
