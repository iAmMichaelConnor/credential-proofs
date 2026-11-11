//! TEST ONLY: unverified evidence for the generator's template checks
//! (`testing/template_*`). `DummyEvidence` verifies nothing. Each `verify`
//! fails closed with `assert(false)`, so a template artifact that takes it
//! can authorise nothing, even if someone deploys it. The
//! claim after the assertion only keeps the types and the ABI of the
//! template checks. The template checks only compile the generated contract
//! shape of each use case; the core rules are tested in `testing/core_tests`.
use aztec::{context::PrivateContext, protocol::traits::{Deserialize, Serialize}};
use std::meta::derive;
use uc_attribute_gate::{AttributeClaim, AttributeEvidence};
use uc_event_proof::{Event, EventEvidence};
use uc_login_link::{LinkClaim, LoginLink};
use uc_payment_settlement::{Payment, PaymentEvidence};
use uc_trust::{Binding, SET_BY_HOLDER, Trust};
use uc_uniqueness::{UniquenessClaim, UniquenessEvidence};

/// The scheme id of the template checks (not a real scheme).
pub global SCHEME_TEMPLATE: u32 = 9900;

/// Unverified evidence: every field is the prover's choice, and every
/// `verify` fails.
#[derive(Serialize, Deserialize)]
pub struct DummyEvidence {
    pub trust: Trust,
    pub id: Field,
    pub kind: u32,
    pub value: Field,
    pub amount: u128,
    pub issued_at: u64,
}

impl LoginLink for DummyEvidence {
    let SCHEME: u32 = 9900;

    fn verify(self, _context: &mut PrivateContext, challenge: Field) -> LinkClaim {
        assert(false, "TEST ONLY template check: verifies nothing");
        LinkClaim {
            trust: self.trust,
            identity: self.id,
            binding: Binding { value: challenge, set_by: SET_BY_HOLDER },
            issued_at: self.issued_at,
            expires_at: 0,
            bearer: false,
        }
    }
}

impl AttributeEvidence for DummyEvidence {
    let SCHEME: u32 = 9900;

    fn verify(self, _context: &mut PrivateContext, binding: Field) -> AttributeClaim {
        assert(false, "TEST ONLY template check: verifies nothing");
        AttributeClaim {
            trust: self.trust,
            kind: self.kind,
            value: self.value,
            subject: self.id,
            binding: Binding { value: binding, set_by: SET_BY_HOLDER },
            issued_at: self.issued_at,
        }
    }
}

impl UniquenessEvidence for DummyEvidence {
    let SCHEME: u32 = 9900;

    fn verify(self, _context: &mut PrivateContext, binding: Field) -> UniquenessClaim {
        assert(false, "TEST ONLY template check: verifies nothing");
        UniquenessClaim {
            trust: self.trust,
            person: self.id,
            person_kind: self.kind as u8,
            binding: Binding { value: binding, set_by: SET_BY_HOLDER },
            issued_at: self.issued_at,
        }
    }
}

impl PaymentEvidence for DummyEvidence {
    let SCHEME: u32 = 9900;

    fn verify(self, _context: &mut PrivateContext) -> Payment {
        assert(false, "TEST ONLY template check: verifies nothing");
        Payment {
            trust: self.trust,
            payment_id: self.id,
            payee: self.value,
            asset: self.kind as Field,
            amount: self.amount,
            paid_at: self.issued_at,
            reference: Binding { value: self.value, set_by: SET_BY_HOLDER },
        }
    }
}

impl EventEvidence for DummyEvidence {
    let SCHEME: u32 = 9900;

    fn verify(self, _context: &mut PrivateContext) -> Event {
        assert(false, "TEST ONLY template check: verifies nothing");
        Event {
            trust: self.trust,
            event_id: self.id,
            kind: self.kind as Field,
            subject: 0,
            data: self.value,
            occurred_at: self.issued_at,
        }
    }
}
