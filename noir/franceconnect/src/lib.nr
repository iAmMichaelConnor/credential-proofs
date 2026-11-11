//! FranceConnect+ original ES256 inner JWS. JWE decryption occurs outside Noir.
//!
//! - `verify_franceconnect`: FranceConnect+, issuer
//!   `https://auth.franceconnect.gouv.fr/api/v2` (or the `integration`
//!   issuer `https://auth.integ01.dev-franceconnect.fr/api/v2`), `minimum_acr`
//!   2 or 3.
//! - `verify_franceconnect_v2`: ordinary FranceConnect, issuer
//!   `https://oidc.franceconnect.gouv.fr/api/v2` (or the `sandbox` issuer
//!   `https://fcp-low.sbx.dev-franceconnect.fr/api/v2`), `minimum_acr` 1 to 3.
//!
//! Both use an enrolled `TrustedP256Key`, the `PROFILE_AMR` claim profile and
//! caller obligations of `oidc`, and require one root `acr` whose rank
//! (`eidas1..3` -> 1..3, anything else 0) is at least `minimum_acr`. The two
//! platforms have distinct issuers and their assurance is not interchangeable.
//! The environment flag and `minimum_acr` are enrolled policy.
use oidc::{
    assert_claims_policy, assert_claims_policy_with_iat, Claims, ClaimsWithIat, JwtInput,
    literal_vec, PROFILE_AMR, string_matches, TrustedP256Key,
};
pub fn issuer(integration: bool) -> BoundedVec<u8, 256> {
    if integration {
        literal_vec("https://auth.integ01.dev-franceconnect.fr/api/v2")
    } else {
        literal_vec("https://auth.franceconnect.gouv.fr/api/v2")
    }
}
pub fn assurance_rank(acr: BoundedVec<u8, 256>) -> u8 {
    if string_matches(acr, literal_vec("eidas1")) {
        1
    } else if string_matches(acr, literal_vec("eidas2")) {
        2
    } else if string_matches(acr, literal_vec("eidas3")) {
        3
    } else {
        0
    }
}
pub fn verify_franceconnect<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    integration: bool,
    minimum_acr: u8,
    key: TrustedP256Key,
) -> Claims {
    assert((minimum_acr == 2) | (minimum_acr == 3), "invalid FranceConnect+ assurance policy");
    let payload = token.verify_es256_payload(key);
    let (claims, acr) = oidc::claims_with_required_string(payload, PROFILE_AMR, "acr");
    assert_claims_policy(claims, issuer(integration), audience, subject, nonce, now);
    assert(assurance_rank(acr) >= minimum_acr, "FranceConnect+ assurance below policy");
    claims
}

/// As `verify_franceconnect`, and also returns the signed `iat`: the
/// token must carry exactly one unsigned-integer `iat`, not after `now`.
/// `verify_franceconnect` keeps its domain (there `iat` is not read).
pub fn verify_franceconnect_with_iat<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    integration: bool,
    minimum_acr: u8,
    key: TrustedP256Key,
) -> ClaimsWithIat {
    let (claims, _) = verify_franceconnect_with_iat_and_assurance(
        token,
        audience,
        subject,
        nonce,
        now,
        integration,
        minimum_acr,
        key,
    );
    claims
}

/// Verify the same FC+ domain and return the actual signed eIDAS rank (2 or 3),
/// not minimum_acr. Claims and rank come from one validated signed payload parse.
pub fn verify_franceconnect_with_iat_and_assurance<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    integration: bool,
    minimum_acr: u8,
    key: TrustedP256Key,
) -> (ClaimsWithIat, u8) {
    assert((minimum_acr == 2) | (minimum_acr == 3), "invalid FranceConnect+ assurance policy");
    let payload = token.verify_es256_payload(key);
    let (result, acr) = oidc::claims_with_iat_and_required_string(payload, PROFILE_AMR, "acr");
    assert_claims_policy_with_iat(result, issuer(integration), audience, subject, nonce, now);
    let assurance = assurance_rank(acr);
    assert(assurance >= minimum_acr, "FranceConnect+ assurance below policy");
    (result, assurance)
}
#[test]
fn supported_assurance_is_explicit() {
    assert(assurance_rank(literal_vec("eidas1")) == 1);
    assert(assurance_rank(literal_vec("eidas2")) == 2);
    assert(assurance_rank(literal_vec("eidas3")) == 3);
    assert(assurance_rank(literal_vec("unknown")) == 0);
}

/// Ordinary FranceConnect v2: explicit production/sandbox issuer, ES256 only.
/// A stronger required minimum remains a caller policy, never inferred from token.
pub fn verify_franceconnect_v2<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    sandbox: bool,
    minimum_acr: u8,
    key: TrustedP256Key,
) -> Claims {
    assert((minimum_acr >= 1) & (minimum_acr <= 3), "invalid FranceConnect v2 assurance policy");
    let expected_issuer = if sandbox {
        literal_vec("https://fcp-low.sbx.dev-franceconnect.fr/api/v2")
    } else {
        literal_vec("https://oidc.franceconnect.gouv.fr/api/v2")
    };
    let payload = token.verify_es256_payload(key);
    let (claims, acr) = oidc::claims_with_required_string(payload, PROFILE_AMR, "acr");
    assert_claims_policy(claims, expected_issuer, audience, subject, nonce, now);
    assert(assurance_rank(acr) >= minimum_acr, "FranceConnect v2 assurance below policy");
    claims
}
pub mod benchmarks;
