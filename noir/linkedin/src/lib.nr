//! LinkedIn OIDC RSA4096 bearer-token verification.
//!
//! LinkedIn's published ID-token claim list omits nonce, so no signed claim
//! carries a value that the client or the user chose. This API therefore
//! models possession of a valid, private-witness bearer ID token, not
//! action-bound authorization. LinkedIn, the relying party that received the
//! token, and anyone else who obtains it can present it for its enrolled
//! subject until expiry. Do not use it to authorize an arbitrary transaction
//! (account authorization). Its use-case example is a bearer login link
//! (aztec/use-cases/login-link/linkedin, `OidcBearerLink`).
//!
//! Checks: header `typ` = `JWT`; a bounded structured JSON payload; root `iss`
//! `https://www.linkedin.com`; `aud` and `sub` equal the nonempty enrolled
//! values; a present `azp` equals `aud`; `exp > now`, `iat <= now`, a present
//! `nbf <= now`; selected members are unique root members. The key, audience
//! and subject come from enrolled state and `now` is a trusted time.
use oidc::{
    assert_json_document, json_member, json_optional_member, json_string, json_u64, JwtInput,
    literal_vec, string_matches, TrustedRsa4096Key,
};

/// The signed times of a verified LinkedIn ID token.
pub struct LinkedInTimes {
    /// The signed exclusive expiry (`exp`); `exp > now`.
    pub expiry: u64,
    /// The signed issue time (`iat`); `iat <= now`.
    pub issued_at: u64,
}

/// Verify the token signature with the enrolled RSA4096 public key and bind
/// direct top-level LinkedIn identity/time claims to account policy.
pub fn verify_linkedin_bearer<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    now: u64,
    trusted_key: TrustedRsa4096Key,
) -> u64 {
    verify_linkedin_bearer_times(token, audience, subject, now, trusted_key).expiry
}

/// As `verify_linkedin_bearer`, and also returns the signed `iat`. A
/// consumer that limits the age of a bearer token must use this signed
/// value, not a value derived from `exp`.
pub fn verify_linkedin_bearer_times<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    now: u64,
    trusted_key: TrustedRsa4096Key,
) -> LinkedInTimes {
    assert(
        (audience.len() > 0) & (subject.len() > 0),
        "LinkedIn audience and subject must be nonempty",
    );
    let payload = token.verify_rs256_4096_typed_payload(
        trusted_key,
        BoundedVec::<u8, 32>::from_array("JWT".as_bytes()),
        false,
    );
    validate_linkedin_bearer_claims(payload, audience, subject, now)
}

fn validate_linkedin_bearer_payload<let P: u32, let A: u32, let U: u32>(
    payload: BoundedVec<u8, P>,
    expected_audience: BoundedVec<u8, A>,
    expected_subject: BoundedVec<u8, U>,
    now: u64,
) -> u64 {
    validate_linkedin_bearer_claims(payload, expected_audience, expected_subject, now).expiry
}

fn validate_linkedin_bearer_claims<let P: u32, let A: u32, let U: u32>(
    payload: BoundedVec<u8, P>,
    expected_audience: BoundedVec<u8, A>,
    expected_subject: BoundedVec<u8, U>,
    now: u64,
) -> LinkedInTimes {
    // Validate the entire signed JSON value before selecting direct members;
    // nested shadow claims cannot replace identity fields.
    let root = assert_json_document(payload);
    let issuer = json_string::<P, 256>(payload, json_member(payload, root, "iss"));
    let audience = json_string::<P, 256>(payload, json_member(payload, root, "aud"));
    let subject = json_string::<P, 256>(payload, json_member(payload, root, "sub"));
    let expiry = json_u64(payload, json_member(payload, root, "exp"));
    let issued_at = json_u64(payload, json_member(payload, root, "iat"));
    let (nbf_span, has_nbf) = json_optional_member(payload, root, "nbf");
    let not_before = if has_nbf {
        json_u64(payload, nbf_span)
    } else {
        0
    };
    let (azp_span, has_azp) = json_optional_member(payload, root, "azp");
    let authorized_party = if has_azp {
        json_string::<P, 256>(payload, azp_span)
    } else {
        BoundedVec::<u8, 256>::new()
    };
    assert(
        string_matches(issuer, literal_vec("https://www.linkedin.com")),
        "wrong LinkedIn issuer",
    );
    assert(string_matches(audience, expected_audience), "wrong LinkedIn audience");
    assert(string_matches(subject, expected_subject), "wrong LinkedIn subject");
    assert(!has_azp | string_matches(authorized_party, audience), "LinkedIn azp mismatch");
    assert(expiry > now, "LinkedIn token expired");
    assert(issued_at <= now, "LinkedIn token issued in the future");
    assert(!has_nbf | (not_before <= now), "LinkedIn token not active yet");
    LinkedInTimes { expiry, issued_at }
}

#[test]
fn linkedin_bearer_accepts_missing_nonce_and_nested_shadow() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90,\"profile\":{\"sub\":\"attacker\"}}",
    );
    let expiry = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
    assert(expiry == 200);
}

#[test]
fn linkedin_bearer_accepts_and_type_checks_optional_claims() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90,\"nonce\":\"opaque\",\"azp\":\"client\",\"nbf\":80}",
    );
    assert(
        validate_linkedin_bearer_payload(
            payload,
            literal_vec("client"),
            literal_vec("pairwise-user"),
            100,
        )
            == 200,
    );
}

#[test]
fn linkedin_bearer_returns_the_signed_issue_time() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90}",
    );
    let times = validate_linkedin_bearer_claims(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
    assert((times.expiry == 200) & (times.issued_at == 90));
}

#[test(should_fail_with = "duplicate selected JSON member")]
fn linkedin_bearer_rejects_duplicate_issue_time() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":1,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_claims(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "duplicate selected JSON member")]
fn linkedin_bearer_rejects_duplicate_claim_even_when_first_has_wrong_type() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":null,\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "wrong LinkedIn issuer")]
fn linkedin_bearer_rejects_wrong_issuer() {
    let payload = literal_vec(
        "{\"iss\":\"https://evil.example\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "wrong LinkedIn audience")]
fn linkedin_bearer_rejects_wrong_audience() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"other-client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "wrong LinkedIn subject")]
fn linkedin_bearer_rejects_wrong_subject() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"other-user\",\"exp\":200,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "LinkedIn token expired")]
fn linkedin_bearer_rejects_expired_token() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":100,\"iat\":90}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "LinkedIn token issued in the future")]
fn linkedin_bearer_rejects_future_iat() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":101}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "LinkedIn token not active yet")]
fn linkedin_bearer_rejects_future_nbf() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90,\"nbf\":101}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test]
fn linkedin_bearer_accepts_u64_max_expiry_without_wrap() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":18446744073709551615,\"iat\":0}",
    );
    assert(
        validate_linkedin_bearer_payload(
            payload,
            literal_vec("client"),
            literal_vec("pairwise-user"),
            18446744073709551614,
        )
            == 18446744073709551615,
    );
}

// The shared whole-document validator rejects an integer above 2^64 - 1
// before claim selection reaches us.
#[test(should_fail_with = "invalid JSON scalar")]
fn linkedin_bearer_rejects_expiry_above_u64_max() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":18446744073709551616,\"iat\":0}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}

#[test(should_fail_with = "LinkedIn azp mismatch")]
fn linkedin_bearer_rejects_mismatched_authorized_party() {
    let payload = literal_vec(
        "{\"iss\":\"https://www.linkedin.com\",\"aud\":\"client\",\"sub\":\"pairwise-user\",\"exp\":200,\"iat\":90,\"azp\":\"other\"}",
    );
    let _ = validate_linkedin_bearer_payload(
        payload,
        literal_vec("client"),
        literal_vec("pairwise-user"),
        100,
    );
}
mod benchmarks;
mod known_answer_tests;
