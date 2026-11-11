// Plain unit tests of the adapter's pure helpers; the attestation tests are
// TXE tests in payment-settlement/peer_v4/src/test.nr.
use crate::{asset, canonical_field, payee, word_u128};

#[test]
fn payee_and_asset_are_separated() {
    let a = [1; 32];
    let b = [2; 32];
    assert(payee(a, b) != payee(b, a));
    assert(asset(a) != payee(a, [0; 32]));
}

#[test]
fn intent_hash_below_the_modulus_is_accepted() {
    let mut word = [0; 32];
    word[31] = 7;
    assert_eq(canonical_field(word), 7);
}

#[test(should_fail_with = "Intent hash is not a field element")]
fn intent_hash_above_the_modulus_rejected() {
    let _ = canonical_field([0xff; 32]);
}

#[test(should_fail_with = "Amount exceeds u128")]
fn amount_above_u128_rejected() {
    let mut word = [0; 32];
    word[15] = 1;
    let _ = word_u128(word);
}
