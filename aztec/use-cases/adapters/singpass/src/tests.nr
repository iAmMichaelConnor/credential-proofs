// Plain unit tests of the adapter's pure helpers; the token tests are TXE
// tests in attribute-gating/singpass/src/test.nr.
use crate::{issuer_name, PRODUCTION, SINGPASS_ISSUER, SINGPASS_STAGING_ISSUER, STAGING};

#[test]
fn environments_have_distinct_issuers() {
    assert_eq(issuer_name(PRODUCTION), SINGPASS_ISSUER);
    assert_eq(issuer_name(STAGING), SINGPASS_STAGING_ISSUER);
    assert(SINGPASS_ISSUER != SINGPASS_STAGING_ISSUER);
}

#[test(should_fail_with = "Unknown Singpass environment")]
fn unknown_environment_rejected() {
    let _ = issuer_name(2);
}
