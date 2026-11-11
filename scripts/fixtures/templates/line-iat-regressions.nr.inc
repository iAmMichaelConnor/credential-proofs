#[test]
fn line_signed_iat() {
    let (t, k) = fixture();
    let result = verify_line_with_iat(
        t,
        BoundedVec::<u8, 32>::from_array("1234567890".as_bytes()),
        BoundedVec::<u8, 256>::from_array("U0123456789abcdef0123456789abcdef".as_bytes()),
        BoundedVec::<u8, 64>::from_array(
            "{{NONCE}}".as_bytes(),
        ),
        1900000000,
        k,
    );
    assert(result.issued_at == 1899999940);
    assert(result.claims.expiry == 1900003600);
}
#[test(should_fail_with = "OIDC token issued in the future")]
fn line_iat_after_now_rejected() {
    let (t, k) = fixture();
    let _ = verify_line_with_iat(
        t,
        BoundedVec::<u8, 32>::from_array("1234567890".as_bytes()),
        BoundedVec::<u8, 256>::from_array("U0123456789abcdef0123456789abcdef".as_bytes()),
        BoundedVec::<u8, 64>::from_array(
            "{{NONCE}}".as_bytes(),
        ),
        1899999939,
        k,
    );
}
