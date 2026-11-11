// Plain unit tests of the adapter's pure helpers; the QR tests are TXE tests
// in attribute-gating/aadhaar_secure_qr/src/test.nr.
use crate::{credential_id, issuer_pin};

#[test]
fn issuer_pin_covers_the_maximum_age() {
    assert(issuer_pin(5, 10800) != issuer_pin(5, 10799));
    assert(issuer_pin(5, 10800) != issuer_pin(6, 10800));
}

#[test]
fn credential_id_depends_on_key_and_signature() {
    let mut signature = [0; 18];
    signature[0] = 1;
    let a = credential_id(5, signature);
    assert(a != credential_id(6, signature));
    signature[17] = 1;
    assert(a != credential_id(5, signature));
}
