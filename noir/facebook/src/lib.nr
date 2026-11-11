//! Facebook Limited Login identity-token verification.
//!
//! This direct provider-signed route is for the iOS Limited Login flow. The
//! app passes its action nonce as the SDK's `LoginConfiguration.nonce`; the
//! SDK sends that value as the authorization `nonce` and checks the same
//! expected value on callback. This wrapper therefore compares the signed
//! claim to the account action nonce without a Firebase-specific hash step.
//!
//! `verify_facebook` checks an RS256 token under an RSA-2048 key with issuer
//! `https://www.facebook.com`, nonempty audience and subject, and the flat
//! claim profile and caller obligations of `oidc`. Generic OAuth access tokens
//! are not accepted.
use oidc::{Claims, ClaimsWithIat, JwtInput, literal_vec, TrustedRsaKey};

fn facebook_issuer() -> BoundedVec<u8, 256> {
    literal_vec("https://www.facebook.com")
}

pub fn verify_facebook<let H: u32, let P: u32, let S: u32, let N: u32, let U: u32, let A: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    expected_nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> Claims {
    assert(
        (audience.len() > 0) & (subject.len() > 0),
        "Facebook audience and subject must be nonempty",
    );
    token.verify(facebook_issuer(), audience, subject, expected_nonce, now, trusted_key)
}

/// As `verify_facebook`, and also returns the signed `iat`: the
/// token must carry exactly one unsigned-integer `iat`, not after `now`.
/// `verify_facebook` keeps its domain (there `iat` is not read).
pub fn verify_facebook_with_iat<let H: u32, let P: u32, let S: u32, let N: u32, let U: u32, let A: u32>(
    token: JwtInput<H, P, S>,
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    expected_nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    assert(
        (audience.len() > 0) & (subject.len() > 0),
        "Facebook audience and subject must be nonempty",
    );
    token.verify_profile_with_iat(
        facebook_issuer(),
        audience,
        subject,
        expected_nonce,
        now,
        trusted_key,
        oidc::PROFILE_FLAT,
    )
}
mod benchmarks;
mod known_answer_tests;
