use crate::{assert_cilogon_affiliation, assert_scoped_affiliation};
use crate::fixture::direct_issuer_fixture;
use crate::fixture::{
    direct_issuer_payload, duplicate_idp_payload, fixture_payload, future_nbf_payload,
    missing_idp_payload, social_idp_payload,
};
use crate::fixture::{
    duplicate_idp_fixture, fixture, future_nbf_fixture, missing_idp_fixture, social_idp_fixture,
};
use crate::validate_login_claims;
#[test]
fn login_identity_valid_cilogon_login() {
    let (_t, _k, p, n) = fixture();
    let c = validate_login_claims(fixture_payload(), p, n, 1900000000, true);
    assert(c.expiry == 1900003600);
}
#[test(should_fail_with = "wrong original university idp")]
fn login_identity_wrong_idp() {
    let (_t, _k, mut p, n) = fixture();
    p.institutional_idp = oidc::literal_vec("urn:wrong:campus");
    let _c = validate_login_claims(fixture_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "wrong university nonce")]
fn login_context_wrong_nonce() {
    let (_t, _k, p, _) = fixture();
    let _c = validate_login_claims(
        fixture_payload(),
        p,
        oidc::literal_vec("wrong"),
        1900000000,
        true,
    );
}
#[test(should_fail_with = "wrong university audience")]
fn login_context_wrong_audience() {
    let (_t, _k, mut p, n) = fixture();
    p.audience = BoundedVec::<u8, 128>::from_array("wrong".as_bytes());
    let _c = validate_login_claims(fixture_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "university token expired")]
fn login_context_expired() {
    let (_t, _k, p, n) = fixture();
    let _c = validate_login_claims(fixture_payload(), p, n, 1900003600, true);
}
#[test(should_fail_with = "wrong original university idp")]
fn login_identity_signed_social_idp() {
    let (_t, _k, p, n) = social_idp_fixture();
    let _c = validate_login_claims(social_idp_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "missing selected JSON member")]
fn login_identity_signed_missing_idp() {
    let (_t, _k, p, n) = missing_idp_fixture();
    let _c = validate_login_claims(missing_idp_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn login_identity_signed_duplicate_idp() {
    let (_t, _k, p, n) = duplicate_idp_fixture();
    let _c = validate_login_claims(duplicate_idp_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "university token not active")]
fn login_context_signed_future_nbf() {
    let (_t, _k, p, n) = future_nbf_fixture();
    let _c = validate_login_claims(future_nbf_payload(), p, n, 1900000000, true);
}
#[test(should_fail_with = "CILogon requires institutional idp mode")]
fn login_identity_direct_mode_cannot_bypass_cilogon_idp() {
    let (_t, _k, p, n) = fixture();
    let _c = validate_login_claims(fixture_payload(), p, n, 1900000000, false);
}
#[test]
fn affiliation_exact_asserted_affiliation_profiles() {
    assert_cilogon_affiliation(
        oidc::literal_vec(
            "{\"affiliation\":\"student@example.edu;member@example.edu\"}",
        ),
        oidc::literal_vec("student@example.edu"),
    );
    assert_scoped_affiliation(
        oidc::literal_vec(
            "{\"eduPersonScopedAffiliation\":[\"member@stanford.edu\",\"staff@stanford.edu\"]}",
        ),
        oidc::literal_vec("staff@stanford.edu"),
        1,
    );
    assert_scoped_affiliation(
        oidc::literal_vec("{\"eduperson_scoped_affiliation\":[\"staff@example.edu\"]}"),
        oidc::literal_vec("staff@example.edu"),
        2,
    );
}
#[test(should_fail_with = "missing asserted university affiliation")]
fn affiliation_affiliation_prefix_does_not_match() {
    assert_cilogon_affiliation(
        oidc::literal_vec(
            "{\"affiliation\":\"notstudent@example.edu;member@example.edu\"}",
        ),
        oidc::literal_vec("student@example.edu"),
    );
}
#[test(should_fail_with = "JSON member must be string")]
fn affiliation_affiliation_array_rejects_mixed_types() {
    assert_scoped_affiliation(
        oidc::literal_vec(
            "{\"eduPersonScopedAffiliation\":[\"staff@example.edu\",123]}",
        ),
        oidc::literal_vec("staff@example.edu"),
        1,
    );
}

#[test]
fn login_identity_direct_institution_login() {
    let (_t, _k, mut p, n) = direct_issuer_fixture();
    p.issuer = oidc::literal_vec("https://oidc.example.edu");
    let c = validate_login_claims(direct_issuer_payload(), p, n, 1900000000, false);
    assert(c.expiry == 1900003600);
}
#[test(should_fail_with = "university token issued in future")]
fn login_context_future_iat() {
    let (_t, _k, p, n) = fixture();
    let _c = validate_login_claims(fixture_payload(), p, n, 1899999900, true);
}
// A signed azp must equal the audience.
fn payload_with_azp<let A: u32>(azp: str<A>) -> BoundedVec<u8, 640> {
    let base = fixture_payload();
    let mut out = BoundedVec::<u8, 640>::new();
    out.push(123);
    for b in "\"azp\":\"".as_bytes() {
        out.push(b);
    }
    for b in azp.as_bytes() {
        out.push(b);
    }
    out.push(34);
    out.push(44);
    for i in 1..512 {
        if i < base.len() {
            out.push(base.get(i));
        }
    }
    out
}
#[test]
fn matching_azp_accepted() {
    let (_t, _k, p, n) = fixture();
    let c = validate_login_claims(
        payload_with_azp("cilogon:/client_id/local-synthetic-university"),
        p,
        n,
        1900000000,
        true,
    );
    assert(c.expiry == 1900003600);
}
#[test(should_fail_with = "university azp must match aud")]
fn other_azp_rejected() {
    let (_t, _k, p, n) = fixture();
    let _c = validate_login_claims(
        payload_with_azp("cilogon:/client_id/attacker"),
        p,
        n,
        1900000000,
        true,
    );
}
