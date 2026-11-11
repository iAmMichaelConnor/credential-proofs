use crate::json::{
    Claims, ClaimsWithIat, literal_vec, parse_claims_profile, parse_claims_profile_with_iat,
    PROFILE_FLAT, string_matches,
};
use crate::jwt::{assert_claims_binding, JwtInput, TrustedRsaKey};

/// Google signs either issuer spelling (OpenID Connect documentation,
/// "Validating an ID token"): `https://accounts.google.com` or the bare
/// `accounts.google.com`.
fn assert_google_policy<let AUD: u32, let SUB: u32, let NONCE: u32>(
    claims: Claims,
    expected_audience: BoundedVec<u8, AUD>,
    expected_subject: BoundedVec<u8, SUB>,
    expected_nonce: BoundedVec<u8, NONCE>,
    now: u64,
) {
    assert(
        string_matches(claims.issuer, literal_vec("https://accounts.google.com"))
            | string_matches(claims.issuer, literal_vec("accounts.google.com")),
        "wrong OIDC issuer",
    );
    assert_claims_binding(
        claims,
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
    );
}

/// Verify a Google RS256 ID token against the expected audience, subject and
/// nonce at trusted time `now`, under an enrolled 2048-bit key.
pub fn verify_google<let H: u32, let P: u32, let S: u32, let NONCE: u32, let SUB: u32, let AUD: u32>(
    token: JwtInput<H, P, S>,
    expected_audience: BoundedVec<u8, AUD>,
    expected_subject: BoundedVec<u8, SUB>,
    expected_nonce: BoundedVec<u8, NONCE>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> Claims {
    let payload = token.verify_rs256_payload(trusted_key);
    let claims = parse_claims_profile(payload, PROFILE_FLAT).claims;
    assert_google_policy(
        claims,
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
    );
    claims
}

/// Verify a Sign in with Apple RS256 ID token; as `verify_google` with the
/// issuer `https://appleid.apple.com`.
pub fn verify_apple<let H: u32, let P: u32, let S: u32, let NONCE: u32, let SUB: u32, let AUD: u32>(
    token: JwtInput<H, P, S>,
    expected_audience: BoundedVec<u8, AUD>,
    expected_subject: BoundedVec<u8, SUB>,
    expected_nonce: BoundedVec<u8, NONCE>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> Claims {
    token.verify(
        literal_vec("https://appleid.apple.com"),
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
        trusted_key,
    )
}

/// As `verify_google`, and also returns the signed `iat`: the token must
/// carry exactly one unsigned-integer `iat`, not after `now`.
pub fn verify_google_with_iat<let H: u32, let P: u32, let S: u32, let NONCE: u32, let SUB: u32, let AUD: u32>(
    token: JwtInput<H, P, S>,
    expected_audience: BoundedVec<u8, AUD>,
    expected_subject: BoundedVec<u8, SUB>,
    expected_nonce: BoundedVec<u8, NONCE>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    let payload = token.verify_rs256_payload(trusted_key);
    let result = parse_claims_profile_with_iat(payload, PROFILE_FLAT);
    assert_google_policy(
        result.claims,
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
    );
    assert(result.issued_at <= now, "OIDC token issued in the future");
    result
}

/// As `verify_apple`, and also returns the signed `iat`: the token must
/// carry exactly one unsigned-integer `iat`, not after `now`.
pub fn verify_apple_with_iat<let H: u32, let P: u32, let S: u32, let NONCE: u32, let SUB: u32, let AUD: u32>(
    token: JwtInput<H, P, S>,
    expected_audience: BoundedVec<u8, AUD>,
    expected_subject: BoundedVec<u8, SUB>,
    expected_nonce: BoundedVec<u8, NONCE>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    token.verify_profile_with_iat(
        literal_vec("https://appleid.apple.com"),
        expected_audience,
        expected_subject,
        expected_nonce,
        now,
        trusted_key,
        PROFILE_FLAT,
    )
}

fn claims_with_issuer<let N: u32>(issuer: str<N>) -> Claims {
    Claims {
        issuer: literal_vec(issuer),
        audience: literal_vec("client"),
        subject: literal_vec("user"),
        nonce: literal_vec("nonce"),
        expiry: 200,
        authorized_party: BoundedVec::new(),
        not_before: 0,
        has_not_before: false,
    }
}

fn check_google_policy(claims: Claims) {
    assert_google_policy(
        claims,
        literal_vec("client"),
        literal_vec("user"),
        literal_vec("nonce"),
        100,
    );
}

#[test]
fn google_policy_accepts_both_issuer_spellings() {
    check_google_policy(claims_with_issuer("https://accounts.google.com"));
    check_google_policy(claims_with_issuer("accounts.google.com"));
}

#[test(should_fail_with = "wrong OIDC issuer")]
fn google_policy_rejects_another_issuer() {
    check_google_policy(claims_with_issuer("https://accounts.google.com.example"));
}

// Only the Google profile accepts the bare issuer: the generic policy compares
// the one expected issuer exactly.
#[test(should_fail_with = "wrong OIDC issuer")]
fn generic_policy_rejects_the_bare_google_issuer() {
    crate::jwt::assert_claims_policy(
        claims_with_issuer("accounts.google.com"),
        literal_vec("https://accounts.google.com"),
        literal_vec("client"),
        literal_vec("user"),
        literal_vec("nonce"),
        100,
    );
}
