//! TXE tests of the native Aadhaar Secure QR gate. Each test deploys the
//! keyless `uc_terms_shell` with this instance's terms and runs `gate` (the
//! call that the generated entrypoint makes) at its address with the QRs from
//! `fixture.nr`. The `aadhaar_secure_qr` library verifies the RSA signature,
//! the layout, the issuance time and the age; the core applies the trust,
//! predicate, binding, freshness and nullifier rules. Tampering cases mutate
//! a valid QR. No verification key, proof or network is involved.
//!
//! The TXE private context has one fixed `msg_sender`. A QR has no field
//! that names the caller and the nullifier does not depend on it, so a
//! presentation from another account is the same evidence; the tests show
//! one use per credential with a second presentation of the same QR.
use crate::fixture::{adult, minor, NOW, QR_MAX_AGE, reissue, REISSUE_ISSUED_AT, turns_18, upstream};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_aadhaar_secure_qr::{
    AadhaarSecureQr, MAX_FUTURE, MIN_INCLUSION_WINDOW, SCHEME_AADHAAR_SECURE_QR, UPSTREAM_TEST_ISSUER_KEY_HASH,
};
use uc_attribute_gate::{
    AttributeClaim, DOMAIN_GATE_TERMS, gate, gate_with_bound_terms, GateTerms, KIND_AGE_AT_LEAST_18, PREDICATE_EQ,
};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_NONE, MAX_BEARER_AGE, SET_BY_NONE, SOURCE_DOCUMENT_ISSUER, terms_commitment, TrustPolicy,
};

global SCOPE: Field = 0xad17;

/// The terms' freshness window. The core limits inclusion to the anchor
/// time plus this window, because the adapter reports the anchor time.
global TERMS_MAX_AGE: u64 = 600;

/// The instance's terms: holders aged at least 18 under the synthetic test
/// key, with QRs at most `QR_MAX_AGE` old; unbound evidence accepted (a QR
/// has no free field).
fn terms() -> GateTerms {
    GateTerms {
        accepted: TrustPolicy {
            source: SOURCE_DOCUMENT_ISSUER,
            issuer: adult().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        kind: KIND_AGE_AT_LEAST_18,
        predicate: PREDICATE_EQ,
        threshold: 1,
        max_age: TERMS_MAX_AGE,
        allow_undated: false,
        allow_unbound: true,
        scope: SCOPE,
    }
}

unconstrained fn deploy(env: &mut TestEnvironment, t: GateTerms) -> AztecAddress {
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(
                DOMAIN_GATE_TERMS,
                SCHEME_AADHAAR_SECURE_QR as Field,
                t.hash(),
            )),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

/// Deploys the shell with `t` and mines a block at `timestamp`, the anchor
/// of the next private context.
unconstrained fn setup_with(t: GateTerms, timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = deploy(&mut env, t);
    env.mine_block_at(timestamp);
    (env, at)
}

unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    setup_with(terms(), timestamp)
}

unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_attribute_gate::gate`.
unconstrained fn gate_at(env: TestEnvironment, at: AztecAddress, t: GateTerms, qr: AadhaarSecureQr) -> AttributeClaim {
    at_shell(env, at, |context| gate(context, t, qr))
}

/// The rules after term binding, with other terms at the same address.
unconstrained fn gate_bound(
    env: TestEnvironment,
    at: AztecAddress,
    t: GateTerms,
    qr: AadhaarSecureQr,
) -> AttributeClaim {
    at_shell(env, at, |context| gate_with_bound_terms(context, t, qr))
}

/// The inclusion deadline that the gate requests.
unconstrained fn expiry(env: TestEnvironment, at: AztecAddress, t: GateTerms, qr: AadhaarSecureQr) -> u64 {
    at_shell(
        env,
        at,
        |context| {
            let _ = gate(context, t, qr);
            (*context).finish().expiration_timestamp
        },
    )
}

/// As `expiry`, anchored at block `block`, whose timestamp must be `anchor`.
unconstrained fn expiry_at_block(
    env: TestEnvironment,
    at: AztecAddress,
    block: u32,
    anchor: u64,
    qr: AadhaarSecureQr,
) -> u64 {
    env.private_context_opts(
        PrivateContextOptions::new().at_contract_address(at).at_anchor_block_number(block),
        |context| {
            assert_eq(context.get_anchor_block_header().timestamp(), anchor);
            let _ = gate(context, terms(), qr);
            (*context).finish().expiration_timestamp
        },
    )
}

/// The same QR with prover-chosen bytes after the signed length, which the
/// library ignores: another witness of the same credential.
fn with_trailing_bytes(mut qr: AadhaarSecureQr) -> AadhaarSecureQr {
    let mut storage = qr.signed_data.storage();
    let length = qr.signed_data.len();
    storage[length] = 7;
    storage[length + 1] = 255;
    qr.signed_data = BoundedVec::from_parts(storage, length);
    qr
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW + 60);
    let anchor = env.last_block_timestamp();
    let qr = adult();
    let claim = gate_at(env, at, terms(), qr);
    assert_eq(claim.kind, KIND_AGE_AT_LEAST_18);
    assert_eq(claim.value, 1);
    assert_eq(claim.subject, qr.credential_id());
    assert_eq(claim.trust.issuer, qr.issuer());
    assert_eq(claim.trust.also_authorised, ALSO_COPY_HOLDER);
    assert_eq(claim.binding.set_by, SET_BY_NONE);
    // The adapter reports the anchor time, not the QR time.
    assert_eq(claim.issued_at, anchor);
}

#[test]
unconstrained fn inclusion_limited_from_the_anchor() {
    let (env, at) = setup(NOW + 60);
    let anchor = env.last_block_timestamp();
    assert_eq(expiry(env, at, terms(), adult()), anchor + TERMS_MAX_AGE);
}

#[test]
unconstrained fn inclusion_limit_does_not_depend_on_the_qr_time() {
    // Two QRs issued 120 s apart, presented at the same anchor block, request
    // the same expiry: the transaction does not reveal the issuance time.
    let (env, at) = setup(REISSUE_ISSUED_AT + 60);
    let anchor = env.last_block_timestamp();
    let block = env.last_block_number();
    let first = expiry_at_block(env, at, block, anchor, adult());
    let second = expiry_at_block(env, at, block, anchor, reissue());
    assert_eq(first, anchor + TERMS_MAX_AGE);
    assert_eq(second, first);
}

#[test]
unconstrained fn terms_maximum_age_capped_by_the_bearer_ceiling() {
    // Terms that allow a day: the adapter keeps the QR at most
    // MAX_BEARER_AGE old at inclusion (QR_MAX_AGE at the anchor, plus the
    // rest of the ceiling), below the core's own cap of MAX_BEARER_AGE.
    let mut t = terms();
    t.max_age = 86400;
    let (env, at) = setup_with(t, NOW + 60);
    let anchor = env.last_block_timestamp();
    assert_eq(expiry(env, at, t, adult()), anchor + MAX_BEARER_AGE - QR_MAX_AGE);
}

#[test]
unconstrained fn qr_age_at_inclusion_bounded_by_the_bearer_ceiling() {
    // Terms below the core's cap but above the remaining ceiling: the
    // adapter's limit applies, and it depends on the anchor only.
    let mut t = terms();
    t.max_age = 7200;
    let (env, at) = setup_with(t, NOW + 60);
    let anchor = env.last_block_timestamp();
    assert(MAX_BEARER_AGE - QR_MAX_AGE < 7200);
    assert_eq(expiry(env, at, t, adult()), anchor + MAX_BEARER_AGE - QR_MAX_AGE);
}

/// Zero is an accepted issuer pin; it restricts QR issuance, not the
/// separate terms freshness window applied to the reported anchor time.
fn zero_age_policy() -> (GateTerms, AadhaarSecureQr) {
    let mut qr = adult();
    qr.max_age = 0;
    let mut t = terms();
    t.accepted.issuer = qr.issuer();
    (t, qr)
}

#[test]
unconstrained fn zero_qr_age_at_the_anchor_accepted() {
    let (t, qr) = zero_age_policy();
    let (env, at) = setup_with(t, NOW);
    assert_eq(expiry(env, at, t, qr), NOW + TERMS_MAX_AGE);
}

#[test]
unconstrained fn zero_qr_age_at_the_future_allowance_accepted() {
    let (t, qr) = zero_age_policy();
    let anchor = NOW - MAX_FUTURE;
    let (env, at) = setup_with(t, anchor);
    assert_eq(expiry(env, at, t, qr), anchor + TERMS_MAX_AGE);
}

#[test(should_fail_with = "Aadhaar QR is too old")]
unconstrained fn zero_qr_age_one_second_before_the_anchor_rejected() {
    let (t, qr) = zero_age_policy();
    let (env, at) = setup_with(t, NOW + 1);
    let _ = gate_at(env, at, t, qr);
}

#[test(should_fail_with = "Aadhaar QR timestamp is in the future")]
unconstrained fn zero_qr_age_beyond_the_future_allowance_rejected() {
    let (t, qr) = zero_age_policy();
    let (env, at) = setup_with(t, NOW - MAX_FUTURE - 1);
    let _ = gate_at(env, at, t, qr);
}

#[test]
unconstrained fn zero_terms_age_requests_expiry_at_the_anchor() {
    let (mut t, qr) = zero_age_policy();
    t.max_age = 0;
    let (env, at) = setup_with(t, NOW);
    // TXE records the requested expiry; it does not check rollup inclusion.
    assert_eq(expiry(env, at, t, qr), NOW);
}

#[test]
unconstrained fn valid_at_the_maximum_qr_age() {
    let (env, at) = setup(NOW + QR_MAX_AGE);
    let _ = gate_at(env, at, terms(), adult());
}

#[test(should_fail_with = "Aadhaar QR is too old")]
unconstrained fn stale_rejected() {
    let (env, at) = setup(NOW + QR_MAX_AGE + 1);
    let _ = gate_at(env, at, terms(), adult());
}

#[test]
unconstrained fn issued_within_the_future_allowance_accepted() {
    // Anchor lag: the QR is issued up to MAX_FUTURE after the anchor block.
    let (env, at) = setup(NOW - MAX_FUTURE);
    let anchor = env.last_block_timestamp();
    assert_eq(expiry(env, at, terms(), adult()), anchor + TERMS_MAX_AGE);
}

#[test(should_fail_with = "Aadhaar QR timestamp is in the future")]
unconstrained fn issued_beyond_the_future_allowance_rejected() {
    let (env, at) = setup(NOW - MAX_FUTURE - 1);
    let _ = gate_at(env, at, terms(), adult());
}

#[test(should_fail_with = "already present")]
unconstrained fn second_use_rejected() {
    // A later presentation of the same credential, with another witness:
    // the per-credential nullifier stops it, whoever submits it.
    let (env, at) = setup(NOW + 60);
    let _ = gate_at(env, at, terms(), adult());
    env.mine_block_at(NOW + 120);
    let other = with_trailing_bytes(adult());
    assert_eq(other.credential_id(), adult().credential_id());
    let _ = gate_at(env, at, terms(), other);
}

#[test]
unconstrained fn reissued_qr_is_a_new_credential() {
    // The subject is the signed QR, not the person: the same person's later
    // QR is accepted again (per-person uniqueness is the uniqueness use case, not this gate).
    let (env, at) = setup(REISSUE_ISSUED_AT + 60);
    let first = gate_at(env, at, terms(), adult());
    let second = gate_at(env, at, terms(), reissue());
    assert(first.subject != second.subject);
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn predicate_false_rejected() {
    // A 10-year-old holder's QR, validly signed under the pinned key.
    let (env, at) = setup(NOW + 60);
    let _ = gate_at(env, at, terms(), minor());
}

#[test]
unconstrained fn eighteenth_birthday_on_the_issuance_date_accepted() {
    let (env, at) = setup(NOW + 60);
    let claim = gate_at(env, at, terms(), turns_18());
    assert_eq(claim.value, 1);
}

#[test(should_fail_with = "Unbound evidence not accepted")]
unconstrained fn wrong_binding_rejected() {
    // A QR has no free field, so it cannot bind the caller. Terms that
    // require a caller binding refuse it.
    let (env, at) = setup(NOW + 60);
    let mut t = terms();
    t.allow_unbound = false;
    let _ = gate_bound(env, at, t, adult());
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn other_qr_maximum_age_rejected() {
    // The QR maximum age is part of the pinned issuer.
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.max_age = QR_MAX_AGE + 1;
    let _ = gate_at(env, at, terms(), qr);
}

#[test(should_fail_with = "Aadhaar QR maximum age leaves too short an inclusion window")]
unconstrained fn qr_maximum_age_above_the_bearer_ceiling_rejected() {
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.max_age = MAX_BEARER_AGE + 1;
    let _ = gate_at(env, at, terms(), qr);
}

#[test(should_fail_with = "Aadhaar QR maximum age leaves too short an inclusion window")]
unconstrained fn qr_maximum_age_at_the_bearer_ceiling_rejected() {
    // The adapter's limit would be the anchor time itself: no transaction
    // could be included.
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.max_age = MAX_BEARER_AGE;
    let _ = gate_at(env, at, terms(), qr);
}

#[test(should_fail_with = "Aadhaar QR maximum age leaves too short an inclusion window")]
unconstrained fn qr_maximum_age_one_second_over_the_window_rejected() {
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.max_age = MAX_BEARER_AGE - MIN_INCLUSION_WINDOW + 1;
    let _ = gate_at(env, at, terms(), qr);
}

#[test]
unconstrained fn qr_maximum_age_that_leaves_the_minimum_window_accepted() {
    // The largest accepted pin, with terms that pin it and allow two hours:
    // the adapter's limit, MIN_INCLUSION_WINDOW after the anchor, applies.
    let mut qr = adult();
    qr.max_age = MAX_BEARER_AGE - MIN_INCLUSION_WINDOW;
    let mut t = terms();
    t.accepted.issuer = qr.issuer();
    t.max_age = 7200;
    let (env, at) = setup_with(t, NOW + 60);
    let anchor = env.last_block_timestamp();
    assert_eq(expiry(env, at, t, qr), anchor + MIN_INCLUSION_WINDOW);
}

#[test]
unconstrained fn upstream_test_key_is_another_issuer() {
    // The upstream test key is published: terms that pin the synthetic key
    // never accept its QRs, and terms must never pin it outside tests. (A
    // TXE test cannot anchor at the 2024 issuance time of this QR: TXE
    // blocks cannot go back in time.)
    let qr = upstream();
    assert_eq(qr.key_hash(), UPSTREAM_TEST_ISSUER_KEY_HASH);
    assert(qr.issuer() != adult().issuer());
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn wrong_key_rejected() {
    // The adult QR's bytes and signature with another modulus: the RSA check
    // fails.
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.modulus = upstream().modulus;
    qr.redc = upstream().redc;
    let _ = gate_at(env, at, terms(), qr);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn changed_signature_rejected() {
    let (env, at) = setup(NOW + 60);
    let mut qr = adult();
    qr.signature[0] += 1;
    let _ = gate_at(env, at, terms(), qr);
}

#[test(should_fail_with = "PKCS#1 v1.5: message hash mismatch")]
unconstrained fn tampered_birth_year_rejected() {
    // The minor's QR with its birth year moved back ten years: the RSA check
    // over the signed bytes fails.
    let (env, at) = setup(NOW + 60);
    let mut qr = minor();
    let mut storage = qr.signed_data.storage();
    let year = qr.delimiters[3] + 1 + 8; // "DD-MM-YYYY": third year digit
    assert_eq(storage[year], 0x38); // 2086
    storage[year] = 0x37; // 2076
    qr.signed_data = BoundedVec::from_parts(storage, qr.signed_data.len());
    let _ = gate_at(env, at, terms(), qr);
}
