// Plain unit tests of the admissibility rule; TXE tests of the entrypoint
// rules are in aztec/use-cases/testing/core_tests.
use crate::{
    AccountGrant, action_hex, assert_admissible, attestor_trust, certified_key_trust, client_bound, holder_bound,
    identity_provider_trust, prover_bound, sender_bound, user_key_trust,
};
use uc_trust::{
    ALSO_ATTESTOR, ALSO_CLIENT_OPERATOR, ALSO_COPY_HOLDER, ALSO_IDP, ALSO_MAIL_OPERATOR, ANCHOR_NONE, Binding,
    SET_BY_CLIENT, SET_BY_HOLDER, SET_BY_MERCHANT, SET_BY_NONE, SET_BY_PAYER, SET_BY_PROVER, SET_BY_SENDER,
    SOURCE_ATTESTOR, SOURCE_CERTIFIED_KEY, SOURCE_CHAIN, SOURCE_DOCUMENT_ISSUER, SOURCE_IDENTITY_PROVIDER,
    SOURCE_PLATFORM, SOURCE_USER_KEY, Trust,
};

fn grant(source: u8, set_by: u8, also: u8, value: Field) -> AccountGrant {
    AccountGrant {
        trust: Trust { source, issuer: 0, anchor_kind: ANCHOR_NONE, anchor: 0, finality: 0, also_authorised: also },
        binding: Binding { value, set_by },
        expiration_timestamp: Option::none(),
        session_nullifier: Option::none(),
    }
}

#[test]
fn category_one_to_four_evidence_is_admissible() {
    assert_admissible(grant(SOURCE_USER_KEY, SET_BY_HOLDER, 0, 5), 5);
    assert_admissible(
        grant(
            SOURCE_IDENTITY_PROVIDER,
            SET_BY_CLIENT,
            ALSO_IDP | ALSO_CLIENT_OPERATOR,
            5,
        ),
        5,
    );
    assert_admissible(grant(SOURCE_ATTESTOR, SET_BY_PROVER, 0, 5), 5);
}

#[test(should_fail_with = "Evidence bound to another action")]
fn wrong_action_rejected() {
    assert_admissible(grant(SOURCE_USER_KEY, SET_BY_HOLDER, 0, 6), 5);
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
fn payment_evidence_rejected() {
    // Payment evidence plus a bolted-on key is not admissible (INV-10).
    assert_admissible(grant(SOURCE_PLATFORM, SET_BY_HOLDER, 0, 5), 5);
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
fn static_document_rejected() {
    assert_admissible(
        grant(SOURCE_DOCUMENT_ISSUER, SET_BY_PROVER, ALSO_COPY_HOLDER, 5),
        5,
    );
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
fn chain_evidence_rejected() {
    assert_admissible(grant(SOURCE_CHAIN, SET_BY_HOLDER, 0, 5), 5);
}

#[test(should_fail_with = "Evidence cannot authorise an account")]
fn unknown_source_rejected() {
    assert_admissible(grant(0, SET_BY_HOLDER, 0, 5), 5);
}

#[test(should_fail_with = "Bearer evidence cannot authorise an account")]
fn bearer_evidence_rejected() {
    // LinkedIn-style evidence: an identity provider token without a nonce.
    assert_admissible(
        grant(SOURCE_IDENTITY_PROVIDER, SET_BY_NONE, ALSO_COPY_HOLDER, 5),
        5,
    );
}

#[test(should_fail_with = "Account evidence must bind a chosen value")]
fn unbound_evidence_rejected() {
    assert_admissible(grant(SOURCE_IDENTITY_PROVIDER, SET_BY_NONE, 0, 5), 5);
}

#[test(should_fail_with = "Account evidence must bind a chosen value")]
fn merchant_chosen_value_rejected() {
    assert_admissible(grant(SOURCE_ATTESTOR, SET_BY_MERCHANT, 0, 5), 5);
}

#[test]
fn action_hex_is_lowercase_and_fixed_width() {
    let hex = action_hex(0x0123456789abcdef);
    let expected = "0123456789abcdef".as_bytes();
    for i in 0..48 {
        assert_eq(hex[i], 48);
    }
    for i in 0..16 {
        assert_eq(hex[48 + i], expected[i]);
    }
}

#[test]
fn literal_trust_values_match_uc_trust() {
    // The account path uses literals for bytecode stability; they must equal the constants.
    let none = |source: u8, issuer: Field, also: u8| {
        Trust { source, issuer, anchor_kind: ANCHOR_NONE, anchor: 0, finality: 0, also_authorised: also }
    };
    assert(user_key_trust() == none(SOURCE_USER_KEY, 0, 0));
    assert(certified_key_trust(7) == none(SOURCE_CERTIFIED_KEY, 7, 0));
    assert(identity_provider_trust(7, ALSO_IDP | ALSO_CLIENT_OPERATOR) == none(SOURCE_IDENTITY_PROVIDER, 7, 3));
    assert(ALSO_IDP | ALSO_MAIL_OPERATOR == 5);
    assert(attestor_trust(7) == none(SOURCE_ATTESTOR, 7, ALSO_ATTESTOR));
    assert(holder_bound(5) == Binding { value: 5, set_by: SET_BY_HOLDER });
    assert(client_bound(5) == Binding { value: 5, set_by: SET_BY_CLIENT });
    assert(sender_bound(5) == Binding { value: 5, set_by: SET_BY_SENDER });
    assert(prover_bound(5) == Binding { value: 5, set_by: SET_BY_PROVER });
    assert_eq(ALSO_COPY_HOLDER, 32);
}

#[test]
fn constructed_grants_are_admissible() {
    let grant = |trust: Trust, binding: Binding| {
        AccountGrant { trust, binding, expiration_timestamp: Option::none(), session_nullifier: Option::none() }
    };
    assert_admissible(grant(user_key_trust(), holder_bound(5)), 5);
    assert_admissible(grant(certified_key_trust(7), holder_bound(5)), 5);
    assert_admissible(grant(identity_provider_trust(7, 3), client_bound(5)), 5);
    assert_admissible(grant(identity_provider_trust(7, 5), sender_bound(5)), 5);
    assert_admissible(grant(attestor_trust(7), prover_bound(5)), 5);
}

#[test(should_fail_with = "Account evidence must bind a chosen value")]
fn payer_chosen_value_rejected() {
    assert_admissible(grant(SOURCE_ATTESTOR, SET_BY_PAYER, 0, 5), 5);
}
