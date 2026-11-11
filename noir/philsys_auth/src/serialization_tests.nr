use crate::fixture::fixture;
use crate::serialization_vectors::{
    HIGH_LATIN1_DIGEST, HIGH_LATIN1_FIRST_NAME, QUESTION_MARKS_DIGEST,
};
use sha256::sha256_var;

/// The issuer signs ñ and Ñ as `?`; the field holds that signed spelling.
#[test]
fn exact_legacy_latin1_serialization() {
    let (mut auth, _) = fixture();
    auth.first_name = BoundedVec::from_array([63, 63]);
    let message = auth.signed_message();
    assert(sha256_var(message.storage(), message.len()) == QUESTION_MARKS_DIGEST);
}

/// Latin-1 bytes other than ñ and Ñ (including their neighbours) are signed
/// unchanged.
#[test]
fn other_latin1_bytes_signed_unchanged() {
    let (mut auth, _) = fixture();
    auth.first_name = BoundedVec::from_array(HIGH_LATIN1_FIRST_NAME);
    let message = auth.signed_message();
    assert(sha256_var(message.storage(), message.len()) == HIGH_LATIN1_DIGEST);
}

// Each signed message has one encoding: the unsigned spellings ñ (241) and
// Ñ (209) are rejected, so a field cannot carry a prover-chosen variant of
// the signed `?`.
#[test(should_fail_with = "PhilSys field must spell an enye as the signed ?")]
fn reject_lower_case_enye() {
    let (mut auth, _) = fixture();
    auth.first_name = BoundedVec::from_array([241, 63]);
    let _message = auth.signed_message();
}

#[test(should_fail_with = "PhilSys field must spell an enye as the signed ?")]
fn reject_upper_case_enye() {
    let (mut auth, _) = fixture();
    auth.last_name = BoundedVec::from_array([77, 85, 209, 79, 90]);
    let _message = auth.signed_message();
}

#[test(should_fail_with = "PhilSys field contains unsupported JSON character")]
fn reject_json_injection() {
    let (mut auth, _) = fixture();
    auth.first_name = BoundedVec::from_array([34]);
    let _message = auth.signed_message();
}
