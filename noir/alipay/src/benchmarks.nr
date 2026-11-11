// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify an Alipay v2 signed body and bind its digest to the requested response.
#[export]
pub(crate) fn alipay_v2_response(
    body: BoundedVec<u8, 512>,
    signature: [Field; 18],
    modulus: [Field; 18],
    // The redc limbs are a private, range-checked Barrett hint: several values
    // verify one key, so a public redc would let one proof match many
    // public-input vectors. The public modulus identifies the key.
    redc: [Field; 18],
    expected_digest: [u8; 32],
) {
    let digest =
        crate::verify_v2_signed_body(body, signature, crate::RSAPubkey::new(modulus, redc));
    assert_eq(digest, expected_digest);
}

// Verify an Alipay v3 response, freshness and the expected user identifier.
#[export]
pub(crate) fn alipay_v3_response(
    timestamp: BoundedVec<u8, 20>,
    nonce: BoundedVec<u8, 128>,
    body: BoundedVec<u8, 512>,
    signature: [Field; 18],
    modulus: [Field; 18],
    // The redc limbs are a private, range-checked Barrett hint: several values
    // verify one key, so a public redc would let one proof match many
    // public-input vectors. The public modulus identifies the key.
    redc: [Field; 18],
    now_ms: u64,
    max_age_ms: u64,
    expected_digest: [u8; 32],
    expected_user_id: BoundedVec<u8, 32>,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(expected_user_id);
    let digest = crate::verify_v3_response(
        timestamp,
        nonce,
        body,
        signature,
        crate::RSAPubkey::new(modulus, redc),
        now_ms,
        max_age_ms,
    );
    assert_eq(digest, expected_digest);
    crate::assert_string_claim(body, "user_id", expected_user_id);
}
