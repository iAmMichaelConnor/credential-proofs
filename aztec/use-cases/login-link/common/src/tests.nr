// Plain unit tests of the context-free login-link rules; TXE tests are in
// aztec/use-cases/testing/core_tests.
use crate::{assert_link_claim, link_challenge, link_nullifier, LinkClaim, LinkTerms, timed_challenge};
use aztec::protocol::{address::AztecAddress, traits::FromField};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, Binding, SET_BY_CLIENT, SET_BY_NONE, SOURCE_IDENTITY_PROVIDER, Trust, TrustPolicy,
};

fn terms(allow_bearer: bool) -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: 3,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        max_age: 600,
        allow_bearer,
        scope: 1,
        round: 0,
    }
}

fn claim(challenge: Field) -> LinkClaim {
    LinkClaim {
        trust: Trust {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: 3,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            finality: 0,
            also_authorised: 0,
        },
        identity: 42,
        binding: Binding { value: challenge, set_by: SET_BY_CLIENT },
        issued_at: 1,
        expires_at: 0,
        bearer: false,
    }
}

fn bearer() -> LinkClaim {
    let mut c = claim(0);
    c.binding.set_by = SET_BY_NONE;
    c.trust.also_authorised = ALSO_COPY_HOLDER;
    c.bearer = true;
    c
}

#[test]
fn bound_login_accepted() {
    assert_link_claim(terms(false), claim(9), 9);
}

#[test(should_fail_with = "Login bound to another challenge")]
fn wrong_challenge_rejected() {
    assert_link_claim(terms(false), claim(8), 9);
}

#[test(should_fail_with = "Bearer login not accepted")]
fn bearer_login_needs_explicit_terms() {
    assert_link_claim(terms(false), bearer(), 9);
}

#[test]
fn bearer_login_accepted_when_the_terms_allow_it() {
    assert_link_claim(terms(true), bearer(), 9);
}

#[test(should_fail_with = "Inconsistent bearer flag")]
fn unbound_login_must_be_labelled_bearer() {
    let mut c = claim(9);
    c.binding.set_by = SET_BY_NONE;
    assert_link_claim(terms(true), c, 9);
}

#[test(should_fail_with = "Untrusted issuer")]
fn wrong_issuer_rejected() {
    let mut c = claim(9);
    c.trust.issuer = 4;
    assert_link_claim(terms(false), c, 9);
}

#[test(should_fail_with = "Missing identity")]
fn missing_identity_rejected() {
    let mut c = claim(9);
    c.identity = 0;
    assert_link_claim(terms(false), c, 9);
}

#[test]
fn challenge_separates_callers_and_rounds() {
    let a = AztecAddress::from_field(1);
    let b = AztecAddress::from_field(2);
    assert(link_challenge(1, 1, a, b, 0) != link_challenge(1, 1, a, a, 0));
    assert(link_challenge(1, 1, a, b, 0) != link_challenge(1, 1, a, b, 1));
    assert(link_challenge(1, 1, a, b, 0) != link_challenge(1, 1, b, b, 0));
    assert(link_nullifier(1, 42) != link_nullifier(2, 42));
}

#[test]
fn timed_challenge_binds_the_challenge_and_the_time() {
    assert(timed_challenge(9, 100) != timed_challenge(9, 101));
    assert(timed_challenge(9, 100) != timed_challenge(10, 100));
    assert(timed_challenge(9, 100) != 9);
}
