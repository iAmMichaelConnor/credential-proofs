//! Kakao Login RS256 ID tokens. The subject is an opaque string.
//! Trust the enrolled provider RSA key, never a key supplied by the token.
//!
//! `verify_kakao` checks an RS256 token under an RSA-2048 key with issuer
//! `https://kauth.kakao.com` and the flat claim profile and caller obligations
//! of `oidc`; the audience is the enrolled application.
use oidc::{Claims, ClaimsWithIat, JwtInput, literal_vec, TrustedRsaKey};
pub fn verify_kakao<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> Claims {
    token.verify(literal_vec("https://kauth.kakao.com"), audience, subject, nonce, now, trusted_key)
}

/// As `verify_kakao`, and also returns the signed `iat`: the token must
/// carry exactly one unsigned-integer `iat`, not after `now`. `verify_kakao`
/// keeps its domain (there `iat` is not read).
pub fn verify_kakao_with_iat<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    token.verify_profile_with_iat(
        literal_vec("https://kauth.kakao.com"),
        audience,
        subject,
        nonce,
        now,
        trusted_key,
        oidc::PROFILE_FLAT,
    )
}
mod benchmarks;
mod known_answer_tests;
