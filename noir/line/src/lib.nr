//! LINE native/SDK/LIFF ES256 ID tokens. Web HS256 tokens are unsupported.
//!
//! `verify_line` checks an ES256 token under an enrolled `TrustedP256Key` with
//! issuer `https://access.line.me`, the channel ID (nonempty decimal digits) as
//! audience, and the `PROFILE_AMR` claim profile and caller obligations of
//! `oidc`. A LINE client that cannot set the ID-token nonce cannot bind an
//! action; check the integration before using this for transaction approval.
use oidc::{Claims, ClaimsWithIat, JwtInput, literal_vec, PROFILE_AMR, TrustedP256Key};
pub fn verify_line<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    channel_id: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedP256Key,
) -> Claims {
    assert_channel_id(channel_id);
    token
        .verify_es256_profile(
            literal_vec("https://access.line.me"),
            channel_id,
            subject,
            nonce,
            now,
            trusted_key,
            PROFILE_AMR,
        )
        .claims
}
/// As `verify_line`, and also returns the signed `iat`: the token
/// must carry exactly one unsigned-integer `iat`, not after `now`.
/// `verify_line` keeps its domain (there `iat` is not read).
pub fn verify_line_with_iat<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    channel_id: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedP256Key,
) -> ClaimsWithIat {
    assert_channel_id(channel_id);
    token.verify_es256_profile_with_iat(
        literal_vec("https://access.line.me"),
        channel_id,
        subject,
        nonce,
        now,
        trusted_key,
        PROFILE_AMR,
    )
}
fn assert_channel_id<let A: u32>(channel_id: BoundedVec<u8, A>) {
    assert(channel_id.len() > 0, "LINE channel ID is empty");
    for i in 0..A {
        if i < channel_id.len() {
            assert(
                (channel_id.storage()[i] >= 48) & (channel_id.storage()[i] <= 57),
                "LINE channel ID must be decimal",
            );
        }
    }
}
mod benchmarks;
mod known_answer_tests;

// Synthetic scalar 42; not issued by LINE.
fn fixture() -> (JwtInput<192, 1024, 86>, TrustedP256Key) {
    (
        JwtInput {
            header_b64: BoundedVec::from_array(
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InN5bnRoZXRpYy1saW5lLWtleSJ9".as_bytes(),
            ),
            payload_b64: BoundedVec::from_array(
                "eyJpc3MiOiJodHRwczovL2FjY2Vzcy5saW5lLm1lIiwiYXVkIjoiMTIzNDU2Nzg5MCIsInN1YiI6IlUwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsIm5vbmNlIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImlhdCI6MTg5OTk5OTk0MCwiZXhwIjoxOTAwMDAzNjAwLCJhbXIiOlsibGluZWF1dG9sb2dpbiJdfQ"
                    .as_bytes(),
            ),
            signature_b64: BoundedVec::from_array(
                "7QswfzSqbZvWQaG8njos3OJ_VEJVtMYOupjdm1oq34CkBeNcBliSHxFHPEQHtz-6wczGDX7Cp8EvZcp7YkbR0w"
                    .as_bytes(),
            ),
        },
        TrustedP256Key {
            public_key_x: [
                103, 128, 197, 252, 112, 39, 94, 44, 112, 97, 160, 231, 135, 123, 177, 116, 222,
                173, 235, 152, 135, 2, 127, 63, 168, 54, 84, 21, 139, 167, 245, 12,
            ],
            public_key_y: [
                60, 186, 140, 52, 188, 53, 210, 14, 129, 247, 48, 172, 28, 123, 214, 214, 97, 169,
                66, 249, 12, 106, 156, 165, 92, 81, 47, 158, 74, 0, 18, 102,
            ],
        },
    )
}
fn check(
    token: JwtInput<192, 1024, 86>,
    key: TrustedP256Key,
    audience: BoundedVec<u8, 32>,
    subject: BoundedVec<u8, 256>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) {
    let _claims = verify_line(token, audience, subject, nonce, now, key);
}
#[test]
fn line_valid() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "wrong OIDC audience")]
fn line_wrong_audience() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    a = BoundedVec::from_array("999".as_bytes());
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "wrong OIDC subject")]
fn line_wrong_subject() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    u = BoundedVec::from_array("wrong".as_bytes());
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "wrong OIDC nonce")]
fn line_wrong_nonce() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    n = BoundedVec::from_array([49; 64]);
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "OIDC token expired")]
fn line_expired() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    now = 1900003600;
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "ES256 signature verification failed")]
fn line_invalid_key() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    k.public_key_x = [0; 32];
    k.public_key_y = [0; 32];
    check(t, k, a, u, n, now);
}
#[test(should_fail_with = "unexpected JWS algorithm")]
fn line_hs256() {
    let (mut t, mut k) = fixture();
    let mut a = BoundedVec::from_array("1234567890".as_bytes());
    let mut u = BoundedVec::from_array("U0123456789abcdef0123456789abcdef".as_bytes());
    let mut n = BoundedVec::from_array(
        "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
    );
    let mut now = 1900000000;
    t.header_b64 = BoundedVec::from_array("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9".as_bytes());
    check(t, k, a, u, n, now);
}
#[test]
fn line_signed_iat() {
    let (t, k) = fixture();
    let result = verify_line_with_iat(
        t,
        BoundedVec::<u8, 32>::from_array("1234567890".as_bytes()),
        BoundedVec::<u8, 256>::from_array("U0123456789abcdef0123456789abcdef".as_bytes()),
        BoundedVec::<u8, 64>::from_array(
            "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
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
            "0000000000000000000000000000000000000000000000000000000000000000".as_bytes(),
        ),
        1899999939,
        k,
    );
}
