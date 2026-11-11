// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a university login token under direct or brokered identity-provider policy.
#[export]
pub fn university_verify_login(
    token: crate::AuthInput,
    trusted_key: oidc::TrustedRsaKey,
    policy: crate::AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
    brokered: bool,
) -> [u128; 18] {
    // The modulus limbs are the public output, which a verifier compares with its
    // trusted key. The redc limbs stay private: they are a range-checked Barrett
    // hint, several values verify one key, and a public redc would let one proof
    // match many public-input vectors.
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(policy.issuer);
    canonical_bytes::assert_canonical(policy.audience);
    canonical_bytes::assert_canonical(policy.subject);
    canonical_bytes::assert_canonical(policy.institutional_idp);
    canonical_bytes::assert_canonical(nonce);
    // Direct (not brokered) mode never reads institutional_idp. It must be empty;
    // with the zero padding above, all its bytes are then zero.
    assert(
        brokered | (policy.institutional_idp.len() == 0),
        "institutional idp must be empty in direct mode",
    );
    let _claims = crate::verify_login(token, trusted_key, policy, nonce, now, brokered);
    trusted_key.modulus_limbs
}

// Validate university login claims under direct or brokered policy without verifying a
// signature.
// Exact same decoded capacity/policy as full encodedP2048 login composition.
// This component does not establish signature authenticity.
#[export]
pub fn university_validate_login_claims(
    payload: BoundedVec<u8, 1536>,
    policy: crate::AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
    brokered: bool,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(policy.issuer);
    canonical_bytes::assert_canonical(policy.audience);
    canonical_bytes::assert_canonical(policy.subject);
    canonical_bytes::assert_canonical(policy.institutional_idp);
    canonical_bytes::assert_canonical(nonce);
    // Direct (not brokered) mode never reads institutional_idp. It must be empty;
    // with the zero padding above, all its bytes are then zero.
    assert(
        brokered | (policy.institutional_idp.len() == 0),
        "institutional idp must be empty in direct mode",
    );
    let _claims = crate::validate_login_claims(payload, policy, nonce, now, brokered);
}
