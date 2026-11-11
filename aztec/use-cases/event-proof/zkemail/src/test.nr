//! TXE tests of the zkEmail event proof. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `on_event` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! emails from `fixture.nr`. The DKIM signature over the rebuilt signing
//! input is verified by `zkemail::dkim::RSAPubkey`. Negative cases mutate the
//! valid fixture. No verification key, proof or network is involved.
use crate::fixture::{email, NOW, OTHER_MODULUS, OTHER_REDC, second_email, SIGNED_AT};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_zkemail::{body, email_kind, mailbox, SCHEME_ZKEMAIL, ZkemailReceivedEmail};
use uc_event_proof::{DOMAIN_EVENT_TERMS, Event, EventTerms, on_event, on_event_with_bound_terms};
use uc_trust::{ALSO_MAIL_OPERATOR, ANCHOR_NONE, SOURCE_IDENTITY_PROVIDER, terms_commitment, TrustPolicy};

/// The instance's deployment terms: the fixture key, domain and selector;
/// emails from the fixture sender with the fixture subject to the fixture
/// recipient; any body; one hour of freshness.
fn terms() -> EventTerms {
    EventTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: email().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: email_kind(email().sender, email().subject),
        match_subject: true,
        subject: mailbox(email().recipient),
        match_data: false,
        data: 0,
        max_age: 3600,
        scope: 1,
    }
}

/// Deploys the shell with `terms()` and mines a block at `timestamp`, the
/// anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_EVENT_TERMS,
                SCHEME_ZKEMAIL as Field,
                terms().hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer();
    env.mine_block_at(timestamp);
    (env, at)
}

/// Runs `f` in a private context at the deployed shell.
unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_event_proof::on_event` with the email.
unconstrained fn observe(env: TestEnvironment, at: AztecAddress, input: ZkemailReceivedEmail) -> Event {
    at_shell(env, at, |context| on_event(context, terms(), input))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn observe_with(env: TestEnvironment, at: AztecAddress, other: EventTerms) -> Event {
    at_shell(
        env,
        at,
        |context| on_event_with_bound_terms(context, other, email()),
    )
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    let event = observe(env, at, email());
    assert_eq(event.trust.issuer, email().issuer());
    assert_eq(event.trust.also_authorised, ALSO_MAIL_OPERATOR);
    assert_eq(event.kind, terms().kind);
    assert_eq(event.subject, terms().subject);
    assert_eq(event.data, body(email().body_hash));
    assert_eq(event.occurred_at, SIGNED_AT);
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // The transaction must be included by t= + max_age.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = on_event(context, terms(), email());
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, SIGNED_AT + 3600);
}

#[test]
unconstrained fn second_email_accepted() {
    // Another signed email of the same kind is another event.
    let (env, at) = setup(NOW);
    let first = observe(env, at, email());
    let second = observe(env, at, second_email());
    assert(first.event_id != second.event_id);
    assert_eq(first.kind, second.kind);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // Another well-formed key: the signature check fails
    // (`mutations_reach_the_signature_check` shows that the key also changes
    // the issuer pin).
    let (env, at) = setup(NOW);
    let mut input = email();
    input.modulus = OTHER_MODULUS;
    input.redc = OTHER_REDC;
    let _ = observe(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn bad_signature_rejected() {
    let (env, at) = setup(NOW);
    let mut input = email();
    input.signature[3] += 1;
    let _ = observe(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_subject_rejected() {
    // The subject is signed: another tag is not this email.
    let (env, at) = setup(NOW);
    let mut input = email();
    let mut subject = input.subject.storage();
    subject[0] = 0x50; // "Prder 42 shipped"
    input.subject = BoundedVec::from_parts(subject, input.subject.len());
    let _ = observe(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_recipient_rejected() {
    let (env, at) = setup(NOW);
    let mut input = email();
    let mut recipient = input.recipient.storage();
    recipient[0] = 0x63; // "cob@inbox.example"
    input.recipient = BoundedVec::from_parts(recipient, input.recipient.len());
    let _ = observe(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_body_hash_rejected() {
    let (env, at) = setup(NOW);
    let mut input = email();
    input.body_hash[0] ^= 1;
    let _ = observe(env, at, input);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_time_rejected() {
    // t= is signed: a prover cannot make the email look younger.
    let (env, at) = setup(NOW);
    let mut input = email();
    input.signed_at += 10;
    let _ = observe(env, at, input);
}

/// The tests below that expect the PKCS#1 v1.5 message fail at the signature check, not
/// earlier: each mutated input still passes the profile checks and differs
/// from the valid one only in signed bytes or in the key.
#[test]
unconstrained fn mutations_reach_the_signature_check() {
    let valid = email().signed_header();
    let mut subject = email();
    let mut storage = subject.subject.storage();
    storage[0] = 0x50;
    subject.subject = BoundedVec::from_parts(storage, subject.subject.len());
    assert(subject.signed_header() != valid);
    let mut recipient = email();
    let mut storage = recipient.recipient.storage();
    storage[0] = 0x63;
    recipient.recipient = BoundedVec::from_parts(storage, recipient.recipient.len());
    assert(recipient.signed_header() != valid);
    let mut time = email();
    time.signed_at += 10;
    assert(time.signed_header() != valid);
    let mut body_hash = email();
    body_hash.body_hash[0] ^= 1;
    assert(body_hash.signed_header() != valid);
    let mut key = email();
    key.modulus = OTHER_MODULUS;
    key.redc = OTHER_REDC;
    assert_eq(key.signed_header(), valid);
    assert(key.issuer() != email().issuer());
}

#[test(should_fail_with = "Wrong event kind")]
unconstrained fn wrong_kind_rejected() {
    // Terms for another subject tag from the same sender.
    let (env, at) = setup(NOW);
    let mut other = terms();
    let mut subject = email().subject.storage();
    subject[0] = 0x50;
    other.kind = email_kind(
        email().sender,
        BoundedVec::from_parts(subject, email().subject.len()),
    );
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Wrong event subject")]
unconstrained fn wrong_recipient_rejected() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.subject += 1;
    let _ = observe_with(env, at, other);
}

#[test]
unconstrained fn matching_body_accepted() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.match_data = true;
    other.data = body(email().body_hash);
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Wrong event data")]
unconstrained fn wrong_body_rejected() {
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.match_data = true;
    let mut hash = email().body_hash;
    hash[31] ^= 1;
    other.data = body(hash);
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn refused_mail_operator_rejected() {
    // The label is visible to the terms: refusing the mail operator refuses
    // every DKIM email.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.accepted.refuse_also = ALSO_MAIL_OPERATOR;
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    let (env, at) = setup(SIGNED_AT + 61);
    let mut other = terms();
    other.max_age = 60;
    let _ = observe_with(env, at, other);
}

#[test(should_fail_with = "Evidence issued after the anchor block")]
unconstrained fn future_email_rejected() {
    let (env, at) = setup(SIGNED_AT - 1);
    let _ = observe(env, at, email());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{observe_with, setup, SIGNED_AT, terms};

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        let (env, at) = setup(SIGNED_AT + 60);
        let mut other = terms();
        other.max_age = 60;
        let _ = observe_with(env, at, other);
    }
}
