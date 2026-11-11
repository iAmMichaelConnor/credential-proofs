//! Institutional OIDC and explicitly trusted CILogon upstream institutions.
//! Signed affiliation is optional and may be cached; it is not current enrollment.
//!
//! `verify_login` verifies an RS256 token under an enrolled RSA-2048 key and a
//! bounded structured payload: `iss`, `aud`, `sub` and `nonce` equal the
//! nonempty `AuthPolicy` values, a present `azp` equals the audience, `exp > now`,
//! `iat <= now`, a present `nbf <= now`. With `brokered` the issuer must be
//! `https://cilogon.org` and the signed `idp` must equal `institutional_idp`, so
//! the trust is in CILogon's signature and its statement of the upstream IdP;
//! without it the issuer must not be CILogon. `AuthPolicy` comes from enrolled
//! state; see `oidc` for the shared caller obligations.
use oidc::{
    assert_json_document, json_member, json_optional_member, json_string, json_u64, JsonSpan,
    JwtInput, literal_vec, string_matches, TrustedRsaKey,
};

pub struct AuthPolicy {
    pub issuer: BoundedVec<u8, 256>,
    pub audience: BoundedVec<u8, 128>,
    pub subject: BoundedVec<u8, 256>,
    /// Required signed upstream entityID in brokered CILogon mode.
    pub institutional_idp: BoundedVec<u8, 256>,
}
pub struct LoginClaims {
    pub expiry: u64,
    pub issued_at: u64,
}
fn root_string<let N: u32>(
    payload: BoundedVec<u8, N>,
    root: JsonSpan,
    name: str<3>,
) -> BoundedVec<u8, 256> {
    json_string(payload, json_member(payload, root, name))
}
/// Verify one-string-audience RS256 OIDC ID token and exact action nonce.
/// brokered=true pins CILogon issuer and requires signed institutional idp.
/// brokered=false pins the direct institution issuer configured by the consumer.
pub fn verify_login<let H: u32, let P: u32, let S: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    key: TrustedRsaKey,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, N>,
    now: u64,
    brokered: bool,
) -> LoginClaims {
    let payload = token.verify_rs256_payload(key);
    validate_login_claims(payload, policy, nonce, now, brokered)
}
/// Validate claims from a signature-verified payload. This pure policy helper
/// does not authenticate unsigned JSON; verify_login binds these exact bytes.
pub fn validate_login_claims<let P: u32, let N: u32>(
    payload: BoundedVec<u8, P>,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, N>,
    now: u64,
    brokered: bool,
) -> LoginClaims {
    assert(
        (policy.issuer.len() > 0)
            & (policy.audience.len() > 0)
            & (policy.subject.len() > 0)
            & (nonce.len() > 0),
        "empty university identity policy",
    );
    assert(payload.len() <= P, "university payload exceeds capacity");
    assert(
        (policy.issuer.len() <= 256)
            & (policy.audience.len() <= 128)
            & (policy.subject.len() <= 256)
            & (policy.institutional_idp.len() <= 256)
            & (nonce.len() <= N),
        "university policy exceeds capacity",
    );
    let root = assert_json_document(payload);
    assert(
        string_matches(root_string(payload, root, "iss"), policy.issuer),
        "wrong university issuer",
    );
    assert(
        string_matches(root_string(payload, root, "aud"), policy.audience),
        "wrong university audience",
    );
    // A present azp must equal the audience, as for the other
    // OIDC profiles (OIDC Core 1.0 section 3.1.3.7).
    let (azp, has_azp) = json_optional_member(payload, root, "azp");
    if has_azp {
        assert(
            string_matches(json_string::<P, 256>(payload, azp), policy.audience),
            "university azp must match aud",
        );
    }
    assert(
        string_matches(root_string(payload, root, "sub"), policy.subject),
        "wrong university subject",
    );
    let signed_nonce: BoundedVec<u8, 256> =
        json_string(payload, json_member(payload, root, "nonce"));
    assert(string_matches(signed_nonce, nonce), "wrong university nonce");
    let expiry = json_u64(payload, json_member(payload, root, "exp"));
    let issued_at = json_u64(payload, json_member(payload, root, "iat"));
    assert(expiry > now, "university token expired");
    assert(issued_at <= now, "university token issued in future");
    let (nbf, present) = json_optional_member(payload, root, "nbf");
    if present {
        assert(json_u64(payload, nbf) <= now, "university token not active");
    }
    if !brokered {
        assert(
            !string_matches(policy.issuer, literal_vec("https://cilogon.org")),
            "CILogon requires institutional idp mode",
        );
    }
    if brokered {
        assert(
            string_matches(policy.issuer, literal_vec("https://cilogon.org")),
            "CILogon issuer must be fixed",
        );
        assert(policy.institutional_idp.len() > 0, "missing trusted institutional idp");
        let signed_idp: BoundedVec<u8, 256> =
            json_string(payload, json_member(payload, root, "idp"));
        assert(
            string_matches(signed_idp, policy.institutional_idp),
            "wrong original university idp",
        );
    }
    LoginClaims { expiry, issued_at }
}
/// CILogon concrete profile. Trusts broker signature AND exact signed original
/// institutional idp; social providers cannot satisfy a pinned campus policy.
pub fn verify_cilogon<let H: u32, let P: u32, let S: u32, let N: u32>(
    token: JwtInput<H, P, S>,
    key: TrustedRsaKey,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, N>,
    now: u64,
) -> LoginClaims {
    verify_login(token, key, policy, nonce, now, true)
}
/// As `verify_cilogon`, and also checks that `affiliation` is one entry of
/// the signed semicolon-delimited `affiliation` claim
/// (`assert_cilogon_affiliation`), over the same signature-verified payload
///. The caller then reports `affiliation` as the asserted value: an
/// exact entry, chosen by the prover from the signed list. As-asserted only:
/// it may be cached by the campus identity provider and is not current
/// enrolment.
pub fn verify_cilogon_with_affiliation<let H: u32, let P: u32, let S: u32, let N: u32, let A: u32>(
    token: JwtInput<H, P, S>,
    key: TrustedRsaKey,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, N>,
    now: u64,
    affiliation: BoundedVec<u8, A>,
) -> LoginClaims {
    let payload = token.verify_rs256_payload(key);
    let claims = validate_login_claims(payload, policy, nonce, now, true);
    assert_cilogon_affiliation(payload, affiliation);
    claims
}
/// Optional check over an already signature-verified payload. CILogon publishes
/// semicolon-delimited `affiliation`, not the Stanford camelCase array claim.
/// This checks exact as-asserted membership only, never freshness/current status.
pub fn assert_cilogon_affiliation<let P: u32, let A: u32>(
    payload: BoundedVec<u8, P>,
    expected: BoundedVec<u8, A>,
) {
    let root = assert_json_document(payload);
    let value: BoundedVec<u8, 256> =
        json_string(payload, json_member(payload, root, "affiliation"));
    assert(expected.len() > 0, "empty university affiliation policy");
    assert(expected.len() <= A, "university affiliation exceeds capacity");
    std::static_assert(A > 0, "affiliation capacity must be positive");
    let mut position = 0u32;
    let mut same = true;
    let mut found = false;
    for i in 0..257 {
        if i <= value.len() {
            let b = value.storage()[if i < 256 { i } else { 0 }];
            if (i == value.len()) | ((i < value.len()) & (b == 59)) {
                found = found | (same & (position == expected.len()));
                position = 0;
                same = true;
            } else {
                same = same
                    & (position < expected.len())
                    & (b == expected.storage()[if position < A { position } else { 0 }]);
                position += 1;
            }
        }
    }
    assert(found, "missing asserted university affiliation");
}
/// Optional direct-institution eduPersonScopedAffiliation array profiles.
/// claim_style=1 is Stanford-style camelCase,2 is explicitly selected snake_case.
/// At most16 strings, each256bytes. No claim that these are freshly checked.
pub fn assert_scoped_affiliation<let P: u32, let A: u32>(
    payload: BoundedVec<u8, P>,
    expected: BoundedVec<u8, A>,
    claim_style: u8,
) {
    assert((claim_style == 1) | (claim_style == 2), "unknown university affiliation claim profile");
    assert(expected.len() > 0, "empty university affiliation policy");
    assert(expected.len() <= A, "university affiliation exceeds capacity");
    let root = assert_json_document(payload);
    let array = if claim_style == 1 {
        json_member(payload, root, "eduPersonScopedAffiliation")
    } else {
        json_member(payload, root, "eduperson_scoped_affiliation")
    };
    let mut found = false;
    for i in 0..16 {
        let (item, present) = oidc::json_array_element(payload, array, i, 16);
        if present {
            let value: BoundedVec<u8, 256> = json_string(payload, item);
            found = found | string_matches(value, expected);
        }
    }
    assert(found, "missing asserted university affiliation");
}

/// Fixed-capacity concrete CILogon account input; generic verification APIs above
/// remain available to direct institutional OIDC consumers.
pub type AuthInput = JwtInput<256, 2048, 344>;
pub fn authorise(
    auth: AuthInput,
    key: TrustedRsaKey,
    policy: AuthPolicy,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> LoginClaims {
    verify_cilogon(auth, key, policy, nonce, now)
}

mod fixture;

mod tests;
pub mod benchmarks;
