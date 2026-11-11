use crate::fixture::fixture;

#[test]
fn verifies_synthetic_issuer_credential() {
    let (auth, policy) = fixture();
    auth.verify(policy);
}

#[test(should_fail_with = "wrong enrolled PhilSys credential")]
fn rejects_wrong_enrolled_credential_digest() {
    let (auth, mut policy) = fixture();
    policy.credential_digest[0] ^= 1;
    auth.verify(policy);
}

// Byte 32 is the low byte of S: R and its hint stay bound, so the signature
// equation is what fails.
#[test(should_fail_with = "Ed25519 signature verification failed")]
fn rejects_changed_issuer_signature() {
    let (mut auth, policy) = fixture();
    auth.signature[32] ^= 1;
    auth.verify(policy);
}

#[test(should_fail_with = "Ed25519 public point hint does not match key bytes")]
fn rejects_wrong_issuer_key() {
    let (auth, mut policy) = fixture();
    policy.issuer_key[0] ^= 1;
    auth.verify(policy);
}
