//! Context-free tests of the Reclaim adapter. The claim verification runs
//! in TXE in the event-proof twitter_reclaim instance
//! (`event-proof/twitter_reclaim/src/test.nr`).
use crate::{
    attestor_issuer, claim_context, claim_kind, handle_id, MAX_CONTEXT, MAX_PARAMETERS, MAX_PROVIDER,
    ReclaimHandleLogin, ReclaimObservation, SCHEME_TWITTER_RECLAIM,
};
use uc_event_proof::EventEvidence;
use uc_login_link::LoginLink;

#[test]
fn scheme_id_is_the_reclaim_account_id() {
    assert_eq(<ReclaimObservation as EventEvidence>::SCHEME, SCHEME_TWITTER_RECLAIM);
}

#[test]
fn issuer_pins_key_and_epoch() {
    let base = attestor_issuer([1; 32], [2; 32], 1);
    assert(base != attestor_issuer([3; 32], [2; 32], 1));
    assert(base != attestor_issuer([1; 32], [3; 32], 1));
    assert(base != attestor_issuer([1; 32], [2; 32], 2));
}

#[test]
fn kind_pins_provider_and_parameters() {
    let mut http = [0; MAX_PROVIDER];
    let mut https = [0; MAX_PROVIDER];
    for i in 0..4 {
        http[i] = "http".as_bytes()[i];
        https[i] = "https".as_bytes()[i];
    }
    https[4] = "https".as_bytes()[4];
    let base = claim_kind(http, 4, [7; 32]);
    assert(base != claim_kind(http, 4, [8; 32]));
    assert(base != claim_kind(https, 5, [7; 32]));
    // A byte past the provider's length does not change the kind.
    assert_eq(base, claim_kind(https, 4, [7; 32]));
}

#[test]
fn context_hash_counts_only_the_context() {
    let mut a = [0; MAX_CONTEXT];
    a[0] = 0x7b;
    let mut b = a;
    b[10] = 0x41;
    assert_eq(claim_context(a, 1), claim_context(b, 1));
    assert(claim_context(a, 1) != claim_context(b, 11));
}

fn bounded<let N: u32, let M: u32>(text: str<M>) -> BoundedVec<u8, N> {
    BoundedVec::from_array(text.as_bytes())
}

fn login() -> ReclaimHandleLogin {
    let mut provider = [0; MAX_PROVIDER];
    for i in 0..4 {
        provider[i] = "http".as_bytes()[i];
    }
    ReclaimHandleLogin {
        attestor_x: [1; 32],
        attestor_y: [2; 32],
        attestor_address: [3; 20],
        epoch: 1,
        provider,
        provider_len: 4,
        parameters_prefix: bounded("{\"screen_name\":\""),
        parameters_suffix: bounded("\"}"),
        parameters_hash: [0; 32],
        provider_hash: [0x2a; 32],
        handle: bounded("Alice_1"),
        session: bounded("session-1"),
        owner: [0; 42],
        timestamp_s: 0,
        identifier: [0; 32],
        signature: [0; 65],
    }
}

#[test]
fn handle_login_scheme_id_is_the_reclaim_account_id() {
    assert_eq(<ReclaimHandleLogin as LoginLink>::SCHEME, SCHEME_TWITTER_RECLAIM);
}

#[test]
fn parameters_put_the_handle_in_the_template() {
    let expected: BoundedVec<u8, MAX_PARAMETERS> = bounded("{\"screen_name\":\"Alice_1\"}");
    assert_eq(login().parameters(), expected);
}

#[test]
fn context_has_the_canonical_bytes() {
    let expected: BoundedVec<u8, MAX_CONTEXT> = bounded(
        "{\"contextAddress\":\"0x0000000000000000000000000000000000000000000000000000000000000007\",\"contextMessage\":\"000000000000000000000000000000000000000000000000000000000000002a\",\"extractedParameters\":{\"username\":\"Alice_1\"},\"providerHash\":\"0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a\",\"reclaimSessionId\":\"session-1\"}",
    );
    assert_eq(login().context(7, 42), expected);
}

#[test]
fn handle_id_ignores_case_only() {
    assert_eq(handle_id(bounded("Alice_1")), handle_id(bounded("aLICE_1")));
    assert(handle_id(bounded("alice_1")) != handle_id(bounded("alice_2")));
    assert(handle_id(bounded("alice")) != handle_id(bounded("alice_")));
}

#[test(should_fail_with = "Unsupported X handle byte")]
fn quote_in_handle_rejected() {
    let _ = handle_id(bounded("al\"ice"));
}

#[test(should_fail_with = "Empty X handle")]
fn empty_handle_rejected() {
    let _ = handle_id(BoundedVec::new());
}

#[test(should_fail_with = "Unsupported Reclaim session byte")]
fn quote_in_session_rejected() {
    let mut input = login();
    input.session = bounded("s\"1");
    let _ = input.verify_login(7, 42, 1);
}

#[test]
fn handle_issuer_pins_the_template_and_provider_hash() {
    let base = login().issuer();
    let mut prefix = login();
    prefix.parameters_prefix = bounded("{\"name\":\"");
    let mut suffix = login();
    suffix.parameters_suffix = bounded("\",\"x\":1}");
    let mut provider_hash = login();
    provider_hash.provider_hash = [0x2b; 32];
    let mut epoch = login();
    epoch.epoch = 2;
    assert(base != prefix.issuer());
    assert(base != suffix.issuer());
    assert(base != provider_hash.issuer());
    assert(base != epoch.issuer());
    // The handle is not part of the issuer.
    let mut other_handle = login();
    other_handle.handle = bounded("bob");
    assert_eq(base, other_handle.issuer());
}
