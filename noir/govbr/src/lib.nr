//! Brazil gov.br RS256 identity and signed account assurance.
//!
//! `verify_govbr` checks an RS256 token under an RSA-2048 key with issuer
//! `https://sso.acesso.gov.br/` (or `https://sso.staging.acesso.gov.br/` when
//! `staging`), the `PROFILE_AMR_SCOPE_RELIABILITY` claim profile and caller
//! obligations of `oidc`, and a signed `reliability_info.level` whose rank
//! (`assurance_rank`) is at least `minimum_level` (1 to 3); it returns the
//! signed expiry. `staging` and `minimum_level` are enrolled policy, never
//! prover choices.
use oidc::{
    ClaimsWithIat, JwtInput, literal_vec, PROFILE_AMR_SCOPE_RELIABILITY, string_matches,
    TrustedRsaKey,
};

pub fn assurance_rank(level: BoundedVec<u8, 256>) -> u8 {
    let bronze = literal_vec("bronze");
    let silver = literal_vec("silver");
    let gold = literal_vec("gold");
    let is_bronze = string_matches(level, bronze);
    let is_silver = string_matches(level, silver);
    let is_gold = string_matches(level, gold);
    assert(is_bronze | is_silver | is_gold, "missing or unknown gov.br assurance level");
    if is_gold {
        3
    } else if is_silver {
        2
    } else {
        1
    }
}
pub fn verify_govbr<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    staging: bool,
    minimum_level: u8,
    trusted_key: TrustedRsaKey,
) -> u64 {
    assert((minimum_level >= 1) & (minimum_level <= 3), "invalid gov.br minimum assurance");
    let issuer = if staging {
        literal_vec("https://sso.staging.acesso.gov.br/")
    } else {
        literal_vec("https://sso.acesso.gov.br/")
    };
    let result = token.verify_profile(
        issuer,
        audience,
        subject,
        nonce,
        now,
        trusted_key,
        PROFILE_AMR_SCOPE_RELIABILITY,
    );
    assert(
        assurance_rank(result.assurance_level) >= minimum_level,
        "gov.br assurance below policy",
    );
    result.claims.expiry
}

/// As `verify_govbr`, and also returns the claims with the signed `iat`
///: the token must carry exactly one unsigned-integer `iat`, not
/// after `now`. `verify_govbr` keeps its domain (there `iat` is not read).
pub fn verify_govbr_with_iat<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    staging: bool,
    minimum_level: u8,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    verify_govbr_with_assurance(
        token,
        audience,
        subject,
        nonce,
        now,
        staging,
        minimum_level,
        trusted_key,
    )
        .claims
}
/// A verified gov.br login with its signed assurance rank.
pub struct GovbrLogin {
    /// The claims and the signed `iat`, as `verify_govbr_with_iat` returns them.
    pub claims: ClaimsWithIat,
    /// `assurance_rank` of the signed `reliability_info.level`: 1 bronze,
    /// 2 silver, 3 gold. At least `minimum_level`.
    pub assurance: u8,
}

/// As `verify_govbr_with_iat`, and also returns the signed assurance rank,
/// so a consumer can compare the level itself instead of only knowing that
/// it is at least `minimum_level`. The checks and the accepted tokens
/// are shared with `verify_govbr_with_iat`.
pub fn verify_govbr_with_assurance<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    staging: bool,
    minimum_level: u8,
    trusted_key: TrustedRsaKey,
) -> GovbrLogin {
    assert((minimum_level >= 1) & (minimum_level <= 3), "invalid gov.br minimum assurance");
    let issuer = if staging {
        literal_vec("https://sso.staging.acesso.gov.br/")
    } else {
        literal_vec("https://sso.acesso.gov.br/")
    };
    let result = token.verify_profile_with_iat(
        issuer,
        audience,
        subject,
        nonce,
        now,
        trusted_key,
        PROFILE_AMR_SCOPE_RELIABILITY,
    );
    let assurance = assurance_rank(result.assurance_level);
    assert(assurance >= minimum_level, "gov.br assurance below policy");
    GovbrLogin { claims: result, assurance }
}
#[test]
fn assurance_levels() {
    assert(assurance_rank(literal_vec("bronze")) == 1);
    assert(assurance_rank(literal_vec("silver")) == 2);
    assert(assurance_rank(literal_vec("gold")) == 3);
}
#[test(should_fail_with = "missing or unknown gov.br assurance level")]
fn reject_unknown_level() {
    let _rank = assurance_rank(literal_vec("platinum"));
}
pub mod benchmarks;
