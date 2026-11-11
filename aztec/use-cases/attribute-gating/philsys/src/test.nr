//! TXE tests of the PhilSys attribute gate. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `gate` (the call that
//! the generated entrypoint makes) at its address with the synthetic QRs from
//! `fixture.nr`. The `philsys_auth` library checks the SHA-256 of the
//! official serialization and the strict Ed25519 signature. Wrong-term cases
//! run `gate_with_bound_terms` with other terms at the same address;
//! tampering cases mutate a valid QR. No verification key, proof or network
//! is involved.
//!
//! Every gate call verifies the QR in the TXE session, inside `gate`. The
//! unconstrained Ed25519 and SHA-512 check makes no oracle call for a long
//! time; scripts/test-use-cases.sh raises nargo's foreign call timeout for it.
//! The adapter's `constrained_claim_of_the_fixture` (adapters/philsys, plain
//! `nargo test`) checks the claim under the ACVM.
use crate::fixture::{enye, enye_resigned, ISSUER_KEY, other_issuer, OTHER_ISSUER_KEY, other_person, qr};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_philsys::{credential_id, issuer_pin, PhilsysQr, SCHEME_PHILSYS};
use uc_attribute_gate::{
    AttributeClaim, AttributeEvidence, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms, KIND_ISSUER_AUTHENTIC,
    PREDICATE_EQ,
};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SET_BY_NONE, SOURCE_DOCUMENT_ISSUER, terms_commitment, TrustPolicy};

/// The instance's terms: a QR signed by the pinned issuer key is authentic
/// (value 1); undated and unbound evidence accepted, as the scheme requires.
fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: issuer_pin(ISSUER_KEY),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_ISSUER_AUTHENTIC,
        predicate: PREDICATE_EQ,
        threshold: 1,
        max_age: 3600,
        allow_undated: true,
        allow_unbound: true,
        scope: 0x9a7e,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_PHILSYS as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

/// Deploys the shell with `terms()` and mines a block, the anchor of the
/// next private context.
unconstrained fn setup() -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, terms());
    env.mine_block();
    (env, at)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_attribute_gate::gate`.
unconstrained fn gate_at<E>(env: TestEnvironment, at: AztecAddress, t: GateTerms, evidence: E) -> AttributeClaim
where
    E: AttributeEvidence,
{
    at_shell(env, at, |context| gate(context, t, evidence))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound<E>(env: TestEnvironment, at: AztecAddress, t: GateTerms, evidence: E) -> AttributeClaim
where
    E: AttributeEvidence,
{
    at_shell(
        env,
        at,
        |context| gate_with_bound_terms(context, t, evidence),
    )
}

/// `enye()` with the signed `?` of its last name replaced by `byte`.
fn enye_as(byte: u8) -> PhilsysQr {
    let mut input = enye();
    let mut storage = input.last_name.storage();
    let mut found = 0;
    for i in 0..input.last_name.len() {
        if storage[i] == 63 {
            storage[i] = byte;
            found += 1;
        }
    }
    assert_eq(found, 1);
    input.last_name = BoundedVec::from_parts(storage, input.last_name.len());
    input
}

/// The claim that the instance's QR must give.
fn expected_claim() -> AttributeClaim {
    AttributeClaim {
        trust: uc_trust::Trust {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: issuer_pin(ISSUER_KEY),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            finality: 0,
            also_authorised: ALSO_COPY_HOLDER,
        },
        kind: KIND_ISSUER_AUTHENTIC,
        value: 1,
        subject: credential_id(ISSUER_KEY, qr().credential_digest),
        binding: uc_trust::Binding { value: 0, set_by: SET_BY_NONE },
        issued_at: 0,
    }
}

#[test]
unconstrained fn fixture_keys_differ() {
    assert_eq(SCHEME_PHILSYS, 71);
    assert(ISSUER_KEY != OTHER_ISSUER_KEY);
    assert_eq(qr().issuer(), issuer_pin(ISSUER_KEY));
    assert_eq(other_issuer().issuer(), issuer_pin(OTHER_ISSUER_KEY));
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup();
    let out = gate_at(env, at, terms(), qr());
    assert(out == expected_claim());
}

#[test]
unconstrained fn undated_evidence_has_no_inclusion_deadline() {
    // The QR carries no presentation time: only the protocol's maximum
    // transaction lifetime limits inclusion, and an old copy works as well.
    let (env, at) = setup();
    let now = env.last_block_timestamp();
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, terms(), qr());
            (*context).finish().expiration_timestamp
        },
    );
    assert(expiry > now + 14400);
}

#[test]
unconstrained fn enye_signed_spelling_accepted() {
    // The official serialization signs an enye as `?`; the fields hold that
    // signed byte. A second valid signature over the same QR gives the same
    // claim: the subject depends on the signed serialization only.
    let claim = enye().claim();
    assert_eq(claim.subject, credential_id(ISSUER_KEY, enye().credential_digest));
    assert(enye_resigned().signature != enye().signature);
    assert(enye_resigned().claim() == claim);
}

#[test(should_fail_with = "PhilSys field must spell an enye as the signed ?")]
unconstrained fn enye_upper_case_spelling_rejected() {
    // Each QR has one encoding: Ñ (209) is not the signed byte.
    let _ = enye_as(209).claim();
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    // The same credential presented again with another valid witness (a
    // second issuer signature over the same QR, another nonce): the subject
    // is the signed serialization's digest, so the second use is refused.
    // The fields have one encoding; see the enye tests.
    let (env, at) = setup();
    let _ = gate_at(env, at, terms(), enye());
    let _ = gate_at(env, at, terms(), enye_resigned());
}

#[test(should_fail_with = "Ed25519 signature verification failed")]
unconstrained fn wrong_key_rejected() {
    // Another key's signature over the same fields, presented under the
    // pinned key.
    let (env, at) = setup();
    let mut input = other_issuer();
    input.issuer_key = ISSUER_KEY;
    input.issuer_hint = qr().issuer_hint;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "Ed25519 public point hint does not match key bytes")]
unconstrained fn key_hint_mismatch_rejected() {
    let (env, at) = setup();
    let mut input = qr();
    input.issuer_hint = other_issuer().issuer_hint;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "wrong enrolled PhilSys credential")]
unconstrained fn wrong_credential_digest_rejected() {
    // Another QR's digest: the subject would change, but the library checks
    // the digest against the signed serialization.
    let (env, at) = setup();
    let mut input = qr();
    input.credential_digest = other_person().credential_digest;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "Ed25519 signature verification failed")]
unconstrained fn bad_signature_rejected() {
    // The scalar half of the signature changed; the point hints still match.
    let (env, at) = setup();
    let mut input = qr();
    input.signature[40] ^= 1;
    let _ = gate_at(env, at, terms(), input);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    let (env, at) = setup();
    let mut t = terms();
    t.threshold = 2;
    let _ = gate_bound(env, at, t, qr());
}

#[test(should_fail_with = "Unbound evidence not accepted")]
unconstrained fn wrong_binding_rejected() {
    // The QR has no free signed field, so it cannot bind the caller: terms
    // that require a binding refuse it.
    let (env, at) = setup();
    let mut t = terms();
    t.allow_unbound = false;
    let _ = gate_bound(env, at, t, qr());
}

#[test(should_fail_with = "Undated evidence not accepted")]
unconstrained fn undated_refused_without_allow_undated() {
    let (env, at) = setup();
    let mut t = terms();
    t.allow_undated = false;
    let _ = gate_bound(env, at, t, qr());
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn copy_holder_refused_when_the_terms_refuse_it() {
    // Terms can refuse copy-holder evidence; PhilSys QRs then never pass.
    let (env, at) = setup();
    let mut t = terms();
    t.accepted.refuse_also = ALSO_COPY_HOLDER;
    let _ = gate_bound(env, at, t, qr());
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{enye_as, gate_at, other_issuer, other_person, qr, setup, terms};

    #[test]
    unconstrained fn another_credential_of_the_issuer_accepted() {
        // One use per credential, not per person: another QR is another subject.
        let (env, at) = setup();
        let first = gate_at(env, at, terms(), qr());
        let second = gate_at(env, at, terms(), other_person());
        assert(first.subject != second.subject);
    }

    #[test(should_fail_with = "PhilSys field must spell an enye as the signed ?")]
    unconstrained fn enye_lower_case_spelling_rejected() {
        // ñ (241) is not the signed byte either.
        let _ = enye_as(241).claim();
    }

    #[test(should_fail_with = "Untrusted issuer")]
    unconstrained fn other_issuer_key_rejected() {
        // A genuine signature by another key: it verifies under that key, whose
        // pin the terms do not accept.
        let (env, at) = setup();
        let _ = gate_at(env, at, terms(), other_issuer());
    }

    #[test(should_fail_with = "wrong enrolled PhilSys credential")]
    unconstrained fn tampered_field_rejected() {
        // The PCN's last digit changed: the serialization no longer has the
        // signed digest.
        let (env, at) = setup();
        let mut input = qr();
        let mut storage = input.pcn.storage();
        storage[input.pcn.len() - 1] = 0x39;
        input.pcn = BoundedVec::from_parts(storage, input.pcn.len());
        let _ = gate_at(env, at, terms(), input);
    }

    #[test(should_fail_with = "wrong enrolled PhilSys credential")]
    unconstrained fn enye_as_another_letter_rejected() {
        let (env, at) = setup();
        let _ = gate_at(env, at, terms(), enye_as(0x4e));
    }
}
