// Plain unit tests of the context-free event rules; TXE tests are in
// aztec/use-cases/testing/core_tests.
use crate::{assert_event_matches, Event, event_nullifier, EventTerms};
use uc_trust::{ANCHOR_PINNED, SOURCE_CHAIN, Trust, TrustPolicy};

fn terms() -> EventTerms {
    EventTerms {
        accepted: TrustPolicy {
            source: SOURCE_CHAIN,
            issuer: 1,
            anchor_kind: ANCHOR_PINNED,
            anchor: 31,
            min_finality: 12,
            refuse_also: 0,
        },
        kind: 44,
        match_subject: true,
        subject: 55,
        match_data: false,
        data: 0,
        max_age: 86400,
        scope: 1,
    }
}

fn event() -> Event {
    Event {
        trust: Trust {
            source: SOURCE_CHAIN,
            issuer: 1,
            anchor_kind: ANCHOR_PINNED,
            anchor: 31,
            finality: 12,
            also_authorised: 0,
        },
        event_id: 66,
        kind: 44,
        subject: 55,
        data: 77,
        occurred_at: 1,
    }
}

#[test]
fn matching_event_accepted() {
    assert_event_matches(terms(), event());
}

#[test(should_fail_with = "Wrong event kind")]
fn wrong_kind_rejected() {
    let mut e = event();
    e.kind = 45;
    assert_event_matches(terms(), e);
}

#[test(should_fail_with = "Wrong event subject")]
fn wrong_subject_rejected() {
    let mut e = event();
    e.subject = 56;
    assert_event_matches(terms(), e);
}

#[test(should_fail_with = "Wrong event data")]
fn wrong_data_rejected_when_matched() {
    let mut t = terms();
    t.match_data = true;
    t.data = 78;
    assert_event_matches(t, event());
}

#[test(should_fail_with = "Untrusted anchor")]
fn untrusted_anchor_rejected() {
    let mut e = event();
    e.trust.anchor = 32;
    assert_event_matches(terms(), e);
}

#[test(should_fail_with = "Insufficient finality")]
fn shallow_event_rejected() {
    let mut e = event();
    e.trust.finality = 11;
    assert_event_matches(terms(), e);
}

#[test(should_fail_with = "Missing event id")]
fn missing_event_id_rejected() {
    let mut e = event();
    e.event_id = 0;
    assert_event_matches(terms(), e);
}

#[test]
fn nullifier_is_per_event_scheme_and_scope() {
    assert(event_nullifier(1, 1, 66) != event_nullifier(2, 1, 66));
    assert(event_nullifier(1, 1, 66) != event_nullifier(1, 2, 66));
    assert(event_nullifier(1, 1, 66) != event_nullifier(1, 1, 67));
}
