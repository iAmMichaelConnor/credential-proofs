//! Tenant-specific Microsoft Entra workforce v2 ID-token authentication.
//!
//! `verify_entra` checks an RS256 v2.0 token under an RSA-2048 key, with the
//! issuer `https://login.microsoftonline.com/<tenant>/v2.0` built from a
//! canonical lowercase tenant GUID (so `common` and `organizations` cannot be
//! enrolled), the flat claim profile and caller obligations of `oidc`, and
//! returns the signed expiry. The signed issuer is the only tenant binding.
//! Outside the profile: sovereign clouds, External ID (CIAM) issuers and group
//! overage objects. A tenant token may identify a guest: it proves the pairwise
//! subject in that tenant, not member type, group membership or employment.
use oidc::{ClaimsWithIat, JwtInput, TrustedRsaKey};

/// Tenant IDs use the canonical lowercase GUID representation. The exact
/// signed issuer binds tenant membership; no email or domain claim is trusted.
pub fn tenant_issuer(tenant: [u8; 36]) -> BoundedVec<u8, 256> {
    let mut issuer = BoundedVec::<u8, 256>::new();
    let prefix = "https://login.microsoftonline.com/".as_bytes();
    for i in 0..34 {
        issuer.push(prefix[i]);
    }
    for i in 0..36 {
        let b = tenant[i];
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(b == 45, "tenant must be a canonical GUID");
        } else {
            assert(
                ((b >= 48) & (b <= 57)) | ((b >= 97) & (b <= 102)),
                "tenant must be a canonical GUID",
            );
        }
        issuer.push(b);
    }
    let suffix = "/v2.0".as_bytes();
    for i in 0..5 {
        issuer.push(suffix[i]);
    }
    issuer
}

pub fn verify_entra<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    tenant: [u8; 36],
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> u64 {
    let claims = token.verify(tenant_issuer(tenant), audience, subject, nonce, now, trusted_key);
    claims.expiry
}

/// As `verify_entra`, and also returns the claims with the signed `iat`
///: the token must carry exactly one unsigned-integer `iat`, not
/// after `now`. `verify_entra` keeps its domain (there `iat` is not read).
pub fn verify_entra_with_iat<let H: u32, let P: u32, let S: u32, let A: u32, let U: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    tenant: [u8; 36],
    audience: BoundedVec<u8, A>,
    subject: BoundedVec<u8, U>,
    nonce: BoundedVec<u8, N>,
    now: u64,
    trusted_key: TrustedRsaKey,
) -> ClaimsWithIat {
    token.verify_profile_with_iat(
        tenant_issuer(tenant),
        audience,
        subject,
        nonce,
        now,
        trusted_key,
        oidc::PROFILE_FLAT,
    )
}

#[test]
fn canonical_tenant_issuer() {
    let issuer = tenant_issuer("12345678-1234-1234-1234-123456789abc".as_bytes());
    let expected =
        "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0".as_bytes();
    assert(issuer.len() == 75);
    for i in 0..75 {
        assert(issuer.storage()[i] == expected[i]);
    }
}
#[test(should_fail_with = "tenant must be a canonical GUID")]
fn reject_common_authority() {
    let _issuer = tenant_issuer("common00-0000-0000-0000-000000000000".as_bytes());
}
pub mod benchmarks;
