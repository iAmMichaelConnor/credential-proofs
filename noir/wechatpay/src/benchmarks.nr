// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a WeChat Pay v3 response and bind its payment facts to the expected order.
// The response digest and every expected payment fact are public: a verifier
// must compare them with its own order and policy. The platform key alone
// does not identify the payment.
#[export]
pub(crate) fn wechatpay_v3_response(
    timestamp: BoundedVec<u8, 20>,
    nonce: BoundedVec<u8, 128>,
    body: BoundedVec<u8, 1024>,
    signature: [Field; 18],
    modulus: [Field; 18],
    // The redc limbs are a private, range-checked Barrett hint: several values
    // verify one key, so a public redc would let one proof match many
    // public-input vectors. The public modulus identifies the key.
    redc: [Field; 18],
    now_seconds: u64,
    max_age_seconds: u64,
    expected_digest: [u8; 32],
    expected_appid: BoundedVec<u8, 128>,
    expected_mchid: BoundedVec<u8, 128>,
    expected_transaction_id: BoundedVec<u8, 128>,
    expected_openid: BoundedVec<u8, 128>,
    expected_attach: BoundedVec<u8, 128>,
    expected_total: u64,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(expected_appid);
    canonical_bytes::assert_canonical(expected_mchid);
    canonical_bytes::assert_canonical(expected_transaction_id);
    canonical_bytes::assert_canonical(expected_openid);
    canonical_bytes::assert_canonical(expected_attach);
    let digest = crate::verify_response(
        timestamp,
        nonce,
        body,
        signature,
        crate::RSAPubkey::new(modulus, redc),
        now_seconds,
        max_age_seconds,
    );
    assert_eq(digest, expected_digest);
    crate::assert_payment_claims(
        body,
        expected_appid,
        expected_mchid,
        expected_transaction_id,
        expected_openid,
        expected_attach,
        expected_total,
    );
}
