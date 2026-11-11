//! Singpass FAPI inner signed ID tokens. Encrypted transport is host-decrypted.
//!
//! `authorise` verifies the ES256 inner JWS (`AuthInput`) under an enrolled
//! `TrustedP256Key` and checks, through `validate_claims`:
//! - issuer `https://id.singpass.gov.sg/fapi`, or
//!   `https://stg-id.singpass.gov.sg/fapi` for staging;
//! - audience, subject and nonce equal the nonempty expected values; `exp > now`,
//!   `iat <= now`, a present `nbf <= now`;
//! - `sub_type` is `user` and there is no `act` member (no delegated actor);
//! - `acr` is `urn:singpass:authentication:loa:1`, `:2` or `:3`, at least
//!   `minimum_assurance`; production requires at least 2.
//! It returns the signed expiry, issue time and assurance. The key and every
//! `AuthPolicy` field come from enrolled state; the nonce is derived from the
//! action and `now` is a trusted time (see `oidc` for the shared obligations).
use oidc::{
    assert_claims_policy, json_member, json_optional_member, json_string, JwtInput, literal_vec,
    parse_document_claims, string_matches, TrustedP256Key,
};
pub type AuthInput = JwtInput<256, 1024, 86>;
pub struct AuthPolicy {
    pub audience: BoundedVec<u8, 128>,
    pub subject: BoundedVec<u8, 256>,
    /// 0=production, 1=official staging. Never inferred from untrusted token.
    pub environment: u8,
    /// Minimum signed authentication assurance: production requires at least 2.
    pub minimum_assurance: u8,
}
pub struct LoginClaims {
    pub expiry: u64,
    pub issued_at: u64,
    pub assurance: u8,
}
pub fn authorise(
    token: AuthInput,
    key: TrustedP256Key,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> LoginClaims {
    let payload = token.verify_es256_payload(key);
    validate_claims(payload, policy, nonce, now)
}
/// Pure claims component, usable only after authenticating these exact bytes.
pub fn validate_claims<let N: u32>(
    payload: BoundedVec<u8, N>,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> LoginClaims {
    assert(
        (policy.environment <= 1)
            & (policy.minimum_assurance >= 1)
            & (policy.minimum_assurance <= 3),
        "invalid Singpass trust profile",
    );
    assert(
        (policy.environment == 1) | (policy.minimum_assurance >= 2),
        "production Singpass requires MFA",
    );
    assert(
        (policy.audience.len() > 0)
            & (policy.audience.len() <= 128)
            & (policy.subject.len() > 0)
            & (policy.subject.len() <= 256)
            & (nonce.len() > 0)
            & (nonce.len() <= 64),
        "invalid Singpass identity policy",
    );
    let issuer = if policy.environment == 0 {
        literal_vec("https://id.singpass.gov.sg/fapi")
    } else {
        literal_vec("https://stg-id.singpass.gov.sg/fapi")
    };
    let parsed = parse_document_claims(payload);
    assert_claims_policy(
        parsed.claims,
        issuer,
        policy.audience,
        policy.subject,
        nonce,
        now,
    );
    assert(parsed.issued_at <= now, "Singpass token issued in future");
    let subject_type: BoundedVec<u8, 256> =
        json_string(payload, json_member(payload, parsed.root, "sub_type"));
    assert(string_matches(subject_type, literal_vec("user")), "unsupported Singpass subject type");
    let (_, has_actor) = json_optional_member(payload, parsed.root, "act");
    assert(!has_actor, "Singpass delegated actor not supported");
    let acr: BoundedVec<u8, 256> = json_string(payload, json_member(payload, parsed.root, "acr"));
    let mut assurance = 0u8;
    if string_matches(acr, literal_vec("urn:singpass:authentication:loa:1")) {
        assurance = 1;
    }
    if string_matches(acr, literal_vec("urn:singpass:authentication:loa:2")) {
        assurance = 2;
    }
    if string_matches(acr, literal_vec("urn:singpass:authentication:loa:3")) {
        assurance = 3;
    }
    assert(assurance >= policy.minimum_assurance, "insufficient Singpass assurance");
    LoginClaims { expiry: parsed.claims.expiry, issued_at: parsed.issued_at, assurance }
}
#[test]
fn official_published_signature() {
    let (t, k, p, n, now) = fixture::official_fixture();
    let c = authorise(t, k, p, n, now);
    assert(c.expiry == 1769740423);
    assert(c.assurance == 1);
}
#[test]
fn local_structured_claims_and_open_amr() {
    let (_, _, p, n, now) = fixture::local_fixture();
    let c = validate_claims(fixture::local_payload(), p, n, now);
    assert(c.assurance == 2);
}
#[test(should_fail_with = "OIDC token expired")]
fn official_sample_current_time_rejected() {
    let (_, _, p, n, _) = fixture::official_fixture();
    let _c = validate_claims(fixture::official_payload(), p, n, 1900000000);
}
#[test(should_fail_with = "wrong OIDC issuer")]
fn staging_cannot_become_production() {
    let (_, _, mut p, n, now) = fixture::official_fixture();
    p.environment = 0;
    p.minimum_assurance = 2;
    let _c = validate_claims(fixture::official_payload(), p, n, now);
}
#[test(should_fail_with = "insufficient Singpass assurance")]
fn assurance_downgrade_rejected() {
    let (_, _, mut p, n, now) = fixture::official_fixture();
    p.minimum_assurance = 2;
    let _c = validate_claims(fixture::official_payload(), p, n, now);
}
#[test(should_fail_with = "Singpass delegated actor not supported")]
fn delegated_actor_rejected() {
    let (_, _, p, n, now) = fixture::local_fixture();
    let _c = validate_claims(fixture::delegated_payload(), p, n, now);
}
#[test(should_fail_with = "Singpass token issued in future")]
fn future_iat_rejected() {
    let (_, _, p, n, now) = fixture::local_fixture();
    let _c = validate_claims(fixture::future_iat_payload(), p, n, now);
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn duplicate_acr_rejected() {
    let (_, _, p, n, now) = fixture::local_fixture();
    let _c = validate_claims(fixture::duplicate_acr_payload(), p, n, now);
}
mod fixture;
mod benchmarks;
mod known_answer_tests;
