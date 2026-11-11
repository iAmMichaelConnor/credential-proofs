//! Event-proof core (use case U5): "this external event happened; a fixed
//! effect happens once per event".
use aztec::{
    context::PrivateContext,
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
};
use std::meta::derive;
use uc_trust::{assert_trust_accepted, Trust, TrustPolicy};

mod tests;

pub global DOMAIN_EVENT: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EVENT_V1".as_bytes()) };
pub global DOMAIN_EVENT_TERMS: Field = comptime { poseidon2_hash_bytes("MIKE_UC_EVENT_TERMS_V1".as_bytes()) };

/// What an adapter proves about one event.
#[derive(Eq, Serialize, Deserialize)]
pub struct Event {
    pub trust: Trust,
    /// DKIM (domain, message hash) or Reclaim claim id: the evidence's own
    /// identity, never a root alone. Nonzero.
    pub event_id: Field,
    /// What happened: (sender domain, subject tag), (emitter, topic0), provider id.
    pub kind: Field,
    /// Whom it is about (mailbox, account, recipient); 0 if none.
    pub subject: Field,
    /// Hash of selected event data.
    pub data: Field,
    pub occurred_at: u64,
}

/// Deployment terms, committed in the contract's `immutables_hash`.
#[derive(Eq, Serialize, Deserialize)]
pub struct EventTerms {
    pub accepted: TrustPolicy,
    pub kind: Field,
    pub match_subject: bool,
    pub subject: Field,
    pub match_data: bool,
    pub data: Field,
    /// Freshness ceiling in seconds; `0xffffffffffffffff` accepts any age.
    pub max_age: u64,
    /// App scope of the one-effect-per-event nullifier.
    pub scope: Field,
}

impl EventTerms {
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// Implemented by an adapter's input struct for each event source.
pub trait EventEvidence {
    let SCHEME: u32;
    fn verify(self, context: &mut PrivateContext) -> Event;
}

/// One effect per event per scheme and app scope (siloed by contract address).
/// It includes the scheme, so one event proven through two adapters of one
/// contract gives two nullifiers.
pub fn event_nullifier(scope: Field, scheme: Field, event_id: Field) -> Field {
    poseidon2_hash([DOMAIN_EVENT, scope, scheme, event_id])
}

/// Event rules that need no context.
pub fn assert_event_matches(terms: EventTerms, event: Event) {
    assert_trust_accepted(event.trust, terms.accepted);
    assert(event.kind == terms.kind, "Wrong event kind");
    if terms.match_subject {
        assert(event.subject == terms.subject, "Wrong event subject");
    }
    if terms.match_data {
        assert(event.data == terms.data, "Wrong event data");
    }
    assert(event.event_id != 0, "Missing event id");
}

/// Applies the fixed effect once per event: binds the terms to the contract,
/// then applies `on_event_with_bound_terms`.
pub fn on_event<E>(context: &mut PrivateContext, terms: EventTerms, evidence: E) -> Event
where
    E: EventEvidence,
{
    uc_trust::bind_terms(
        context,
        DOMAIN_EVENT_TERMS,
        E::SCHEME as Field,
        terms.hash(),
    );
    on_event_with_bound_terms(context, terms, evidence)
}

/// As `on_event`, for a caller that has already authenticated `terms`.
pub fn on_event_with_bound_terms<E>(context: &mut PrivateContext, terms: EventTerms, evidence: E) -> Event
where
    E: EventEvidence,
{
    let event = evidence.verify(context);
    assert_event_matches(terms, event);
    uc_trust::require_fresh(
        context,
        event.occurred_at,
        uc_trust::effective_max_age(terms.max_age, event.trust),
    );
    context.push_nullifier_unsafe(event_nullifier(terms.scope, E::SCHEME as Field, event.event_id));
    event
}
