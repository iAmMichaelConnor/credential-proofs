// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.
//
// Verify a bounded RSA-signed body through the compatibility API and expose its digest.
#[export]
pub(crate) fn zkemail_rsa_signature_compat(
    body: BoundedVec<u8, 512>,
    signature: [Field; 18],
    modulus: [Field; 18],
    // The redc limbs are a private, range-checked Barrett hint: several values
    // verify one key, so a public redc would let one proof match many
    // public-input vectors. The public modulus identifies the key.
    redc: [Field; 18],
    expected_digest: [u8; 32],
) {
    let key = rsa_signature::RSAPubkey::new(modulus, redc);
    assert_eq(key.verify_rsa_sha256_pkcs1v15(body, signature), expected_digest);
    assert_eq(key.verify_dkim_signature(body, signature), expected_digest);
    let legacy_key = crate::dkim::RSAPubkey::new(modulus, redc);
    assert_eq(legacy_key.verify_dkim_signature(body, signature), expected_digest);
    assert_eq(legacy_key.hash(), key.hash());
}
