use crate::{deploy_with_immutables, in_context, requested_expiry};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::TestEnvironment,
};
use uc_event_proof::{DOMAIN_EVENT_TERMS, Event, EventEvidence, EventTerms, on_event, on_event_with_bound_terms};
use uc_trust::{ANCHOR_PINNED, SOURCE_CHAIN, terms_commitment, Trust, TrustPolicy};

global SCHEME: u32 = 9007;

global CHAIN_ID: Field = 1;
global ROOT: Field = 0x3007;
global EMITTER: Field = 0xe1;
global TOPIC: Field = 0x70;

/// A dummy chain log proven against a pinned root.
pub struct DummyLog {
    pub root: Field,
    pub depth: u32,
    pub block: Field,
    pub tx_index: Field,
    pub log_index: Field,
    pub emitter: Field,
    pub topic0: Field,
    pub subject: Field,
    pub data: Field,
    pub block_time: u64,
}

impl EventEvidence for DummyLog {
    let SCHEME: u32 = 9007;

    fn verify(self, _context: &mut PrivateContext) -> Event {
        Event {
            trust: Trust {
                source: SOURCE_CHAIN,
                issuer: CHAIN_ID,
                anchor_kind: ANCHOR_PINNED,
                anchor: self.root,
                finality: self.depth,
                also_authorised: 0,
            },
            // Keyed on the log position, never on the receipts root alone.
            event_id: poseidon2_hash([CHAIN_ID, self.block, self.tx_index, self.log_index]),
            kind: poseidon2_hash([self.emitter, self.topic0]),
            subject: self.subject,
            data: self.data,
            occurred_at: self.block_time,
        }
    }
}

fn terms() -> EventTerms {
    EventTerms {
        accepted: TrustPolicy {
            source: SOURCE_CHAIN,
            issuer: CHAIN_ID,
            anchor_kind: ANCHOR_PINNED,
            anchor: ROOT,
            min_finality: 12,
            refuse_also: 0,
        },
        kind: poseidon2_hash([EMITTER, TOPIC]),
        match_subject: true,
        subject: 55,
        match_data: false,
        data: 0,
        max_age: 86400,
        scope: 1,
    }
}

fn log(log_index: Field, age: u64, now: u64) -> DummyLog {
    DummyLog {
        root: ROOT,
        depth: 12,
        block: 100,
        tx_index: 2,
        log_index,
        emitter: EMITTER,
        topic0: TOPIC,
        subject: 55,
        data: 77,
        block_time: now - age,
    }
}

/// Observes the event and returns the requested inclusion expiry. With `at`,
/// the public `on_event` runs at that deployed contract; without it,
/// `on_event_with_bound_terms` runs at the TXE default address.
unconstrained fn observe_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: EventTerms,
    evidence: DummyLog,
) -> u64 {
    in_context(
        env,
        at,
        |context| {
            let event = if at.is_some() {
                on_event(context, terms, evidence)
            } else {
                on_event_with_bound_terms(context, terms, evidence)
            };
            assert_eq(event.subject, 55);
            requested_expiry(context)
        },
    )
}

unconstrained fn observe(env: TestEnvironment, evidence: DummyLog) {
    let _ = observe_at(env, Option::none(), terms(), evidence);
}

unconstrained fn deploy_event(env: &mut TestEnvironment, terms: EventTerms) -> AztecAddress {
    deploy_with_immutables(
        env,
        terms_commitment(DOMAIN_EVENT_TERMS, SCHEME as Field, terms.hash()),
    )
}

fn data_terms() -> EventTerms {
    let mut t = terms();
    t.match_data = true;
    t.data = 77;
    t
}

#[test]
unconstrained fn event_valid_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    observe(env, log(0, 60, now));
}

#[test(should_fail_with = "already present")]
unconstrained fn event_replay_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    observe(env, log(0, 60, now));
    observe(env, log(0, 60, now));
}

#[test]
unconstrained fn event_next_log_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    observe(env, log(0, 60, now));
    observe(env, log(1, 60, now));
}

#[test(should_fail_with = "Wrong event kind")]
unconstrained fn event_wrong_kind_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = log(0, 60, now);
    other.topic0 = 0x71;
    observe(env, other);
}

#[test(should_fail_with = "Wrong event subject")]
unconstrained fn event_wrong_subject_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = log(0, 60, now);
    other.subject = 56;
    observe(env, other);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn event_stale_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    observe(env, log(0, 86401, now));
}

#[test(should_fail_with = "Untrusted anchor")]
unconstrained fn event_untrusted_anchor_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = log(0, 60, now);
    other.root = ROOT + 1;
    observe(env, other);
}

#[test(should_fail_with = "Insufficient finality")]
unconstrained fn event_insufficient_finality_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = log(0, 60, now);
    other.depth = 11;
    observe(env, other);
}

#[test]
unconstrained fn event_matching_data_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = observe_at(env, Option::none(), data_terms(), log(0, 60, now));
}

#[test(should_fail_with = "Wrong event data")]
unconstrained fn event_wrong_data_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut other = log(0, 60, now);
    other.data = 78;
    let _ = observe_at(env, Option::none(), data_terms(), other);
}

// Inclusion expiry.

#[test]
unconstrained fn event_expiry_is_the_freshness_deadline() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = observe_at(env, Option::none(), terms(), log(0, 60, now));
    assert_eq(expiry, now - 60 + 86400);
}

#[test]
unconstrained fn event_at_the_exact_deadline_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = observe_at(env, Option::none(), terms(), log(0, 86400, now));
    assert_eq(expiry, now);
}

#[test]
unconstrained fn event_any_age_accepted_with_the_maximum_max_age() {
    // `max_age = u64::MAX` accepts any age. The deadline saturates, so only
    // the protocol's maximum transaction lifetime limits inclusion.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut forever = terms();
    forever.max_age = 0xffffffffffffffff;
    let expiry = observe_at(env, Option::none(), forever, log(0, now - 1, now));
    assert(expiry > now + 3600);
}

// The public `on_event` at deployed contracts.

#[test]
unconstrained fn on_event_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_event(&mut env, terms());
    let now = env.last_block_timestamp();
    let _ = observe_at(env, Option::some(at), terms(), log(0, 60, now));
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn on_event_wrong_terms_rejected() {
    // Terms that drop the subject match the contract commits to.
    let mut env = TestEnvironment::new();
    let at = deploy_event(&mut env, terms());
    let now = env.last_block_timestamp();
    let mut loose = terms();
    loose.match_subject = false;
    let _ = observe_at(env, Option::some(at), loose, log(0, 60, now));
}
