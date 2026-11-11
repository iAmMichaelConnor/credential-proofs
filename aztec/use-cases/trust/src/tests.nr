// Plain unit tests of the pure trust rules; no TXE is needed.
use crate::{
    ALSO_ATTESTOR, ALSO_COPY_HOLDER, ANCHOR_L1_MESSAGE, ANCHOR_NONE, ANCHOR_PINNED, ANCHOR_REGISTRY, assert_binding,
    assert_choice_allowed, assert_fresh, assert_trust_accepted, Binding, caller_binding, caller_choice_binding,
    effective_max_age, field_hex, MAX_BEARER_AGE, scoped_nullifier, SET_BY_CLIENT, SET_BY_HOLDER, SET_BY_MERCHANT,
    SET_BY_NONE, SET_BY_PROVER, SET_BY_SENDER, SOURCE_CHAIN, SOURCE_PLATFORM, terms_commitment, Trust, TrustPolicy,
};
use aztec::{
    authwit::account::compute_tx_nullifier,
    protocol::{address::AztecAddress, hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::FromField},
};

fn platform() -> (Trust, TrustPolicy) {
    (
        Trust {
            source: SOURCE_PLATFORM,
            issuer: 11,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            finality: 0,
            also_authorised: 0,
        },
        TrustPolicy {
            source: SOURCE_PLATFORM,
            issuer: 11,
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: ALSO_COPY_HOLDER,
        },
    )
}

fn chain() -> (Trust, TrustPolicy) {
    (
        Trust {
            source: SOURCE_CHAIN,
            issuer: 1,
            anchor_kind: ANCHOR_PINNED,
            anchor: 77,
            finality: 64,
            also_authorised: 0,
        },
        TrustPolicy {
            source: SOURCE_CHAIN,
            issuer: 1,
            anchor_kind: ANCHOR_PINNED,
            anchor: 77,
            min_finality: 64,
            refuse_also: 0,
        },
    )
}

#[test]
fn accepted_trust_passes() {
    let (trust, policy) = platform();
    assert_trust_accepted(trust, policy);
    let (trust, policy) = chain();
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Untrusted evidence source")]
fn wrong_source_rejected() {
    let (mut trust, policy) = platform();
    trust.source = SOURCE_CHAIN;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Untrusted issuer")]
fn wrong_issuer_rejected() {
    let (mut trust, policy) = platform();
    trust.issuer = 12;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Untrusted anchor kind")]
fn wrong_anchor_kind_rejected() {
    let (mut trust, policy) = chain();
    trust.anchor_kind = ANCHOR_REGISTRY;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Untrusted anchor")]
fn wrong_pinned_anchor_rejected() {
    let (mut trust, policy) = chain();
    trust.anchor = 78;
    assert_trust_accepted(trust, policy);
}

#[test]
fn registry_anchor_value_is_proven_by_the_adapter() {
    let (mut trust, mut policy) = chain();
    trust.anchor_kind = ANCHOR_REGISTRY;
    policy.anchor_kind = ANCHOR_REGISTRY;
    trust.anchor = 78;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Anchor kind not implemented")]
fn unimplemented_anchor_kind_rejected() {
    let (mut trust, mut policy) = chain();
    trust.anchor_kind = ANCHOR_L1_MESSAGE;
    policy.anchor_kind = ANCHOR_L1_MESSAGE;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Insufficient finality")]
fn shallow_finality_rejected() {
    let (mut trust, policy) = chain();
    trust.finality = 63;
    assert_trust_accepted(trust, policy);
}

#[test(should_fail_with = "Refused co-authority")]
fn refused_co_authority_rejected() {
    let (mut trust, policy) = platform();
    trust.also_authorised = ALSO_COPY_HOLDER | ALSO_ATTESTOR;
    assert_trust_accepted(trust, policy);
}

#[test]
fn freshness_boundaries() {
    // Inclusive deadline: issued_at + max_age.
    assert_eq(assert_fresh(100, 100, 0), 100);
    assert_eq(assert_fresh(100, 120, 20), 120);
    assert_eq(assert_fresh(100, 110, 20), 120);
    // Saturation near the u64 boundary.
    assert_eq(assert_fresh(0xfffffffffffffff0, 0xfffffffffffffff0, 0xffffffffffffffff), 0xffffffffffffffff);
}

#[test(should_fail_with = "Evidence too old")]
fn stale_evidence_rejected() {
    let _ = assert_fresh(100, 121, 20);
}

#[test(should_fail_with = "Evidence issued after the anchor block")]
fn future_evidence_rejected() {
    let _ = assert_fresh(101, 100, 20);
}

#[test]
fn copies_of_bearer_evidence_have_a_ceiling() {
    let (mut trust, _) = platform();
    assert_eq(effective_max_age(86400, trust), 86400);
    trust.also_authorised = ALSO_COPY_HOLDER;
    assert_eq(effective_max_age(86400, trust), MAX_BEARER_AGE);
    assert_eq(effective_max_age(60, trust), 60);
}

#[test]
fn binding_rules() {
    assert_binding(Binding { value: 5, set_by: SET_BY_PROVER }, 5, false);
    assert_binding(Binding { value: 0, set_by: SET_BY_NONE }, 5, true);
    assert_choice_allowed(Binding { value: 5, set_by: SET_BY_HOLDER });
    assert_choice_allowed(Binding { value: 5, set_by: SET_BY_CLIENT });
    assert_choice_allowed(Binding { value: 5, set_by: SET_BY_SENDER });
}

#[test(should_fail_with = "Evidence bound to another value")]
fn wrong_binding_rejected() {
    assert_binding(Binding { value: 6, set_by: SET_BY_HOLDER }, 5, true);
}

#[test(should_fail_with = "Unbound evidence not accepted")]
fn unbound_evidence_needs_explicit_terms() {
    assert_binding(Binding { value: 5, set_by: SET_BY_NONE }, 5, false);
}

#[test(should_fail_with = "A free choice needs holder-chosen evidence")]
fn prover_set_choice_rejected() {
    assert_choice_allowed(Binding { value: 5, set_by: SET_BY_PROVER });
}

#[test(should_fail_with = "A free choice needs holder-chosen evidence")]
fn merchant_set_choice_rejected() {
    assert_choice_allowed(Binding { value: 5, set_by: SET_BY_MERCHANT });
}

#[test]
fn caller_bindings_separate_callers_contracts_and_choices() {
    let a = AztecAddress::from_field(1);
    let b = AztecAddress::from_field(2);
    let base = caller_binding(9, 1, 1, a, b);
    assert(base != caller_binding(9, 1, 1, b, a));
    assert(base != caller_binding(9, 2, 1, a, b));
    assert(base != caller_binding(8, 1, 1, a, b));
    assert(caller_choice_binding(9, 1, 1, a, b, 0) != caller_choice_binding(9, 1, 1, a, b, 1));
    assert(base != caller_choice_binding(9, 1, 1, a, b, 0));
}

#[test]
fn terms_commitment_separates_domains_and_schemes() {
    let commitment = terms_commitment(3, 7, 99);
    assert(commitment != terms_commitment(4, 7, 99));
    assert(commitment != terms_commitment(3, 8, 99));
    // Account policies use the two-element preimage Poseidon2([scheme, policy_hash]).
    assert(commitment != poseidon2_hash([7, 99]));
}

#[test]
fn scoped_nullifier_separates_domains_and_scopes() {
    let n = scoped_nullifier(1, 2, 3);
    assert(n != scoped_nullifier(2, 2, 3));
    assert(n != scoped_nullifier(1, 3, 3));
    assert(n != scoped_nullifier(1, 2, 4));
}

/// An untagged Poseidon2 bytes hash of a payment id can equal
/// the account transaction nullifier of a chosen nonce when the id starts
/// with the separator bytes and has 27 zero bytes. The tagged three-element
/// form used by the cores does not collide on that crafted input.
#[test]
fn t376_tagged_payment_nullifier_does_not_overlap_the_tx_nullifier() {
    let separator: [u8; 4] = (1025801951 as Field).to_le_bytes();
    let mut crafted: [u8; 32] = [0; 32];
    for i in 0..4 {
        crafted[i] = separator[i];
    }
    crafted[31] = 7;
    // The untagged form overlaps (the reason for the domain tag).
    assert_eq(poseidon2_hash_bytes(crafted), compute_tx_nullifier(7));
    // The tagged form does not.
    let domain = comptime { poseidon2_hash_bytes("MIKE_UC_PAYMENT_V1".as_bytes()) };
    let tagged = scoped_nullifier(domain, 1, poseidon2_hash_bytes(crafted));
    assert(tagged != compute_tx_nullifier(7));
    assert(tagged != poseidon2_hash_bytes(crafted));
}

#[test]
fn field_hex_is_lowercase_and_fixed_width() {
    let hex = field_hex(0xab);
    for i in 0..62 {
        assert_eq(hex[i], 48);
    }
    assert_eq(hex[62], 97);
    assert_eq(hex[63], 98);
}

// Reference preimages are written out independently of the packing helpers.
#[test]
fn byte_word_halves_are_big_endian_and_do_not_reduce() {
    let word = [0xff; 32];
    let (high, low) = crate::bytes::halves(word);
    assert_eq(high, 0xffffffffffffffffffffffffffffffff);
    assert_eq(low, 0xffffffffffffffffffffffffffffffff);
    let mut markers = [0; 32];
    markers[0] = 1;
    markers[31] = 2;
    assert_eq(crate::bytes::halves(markers), (0x01000000000000000000000000000000, 2));
}

#[test]
fn byte_hashes_keep_capacity_length_and_padding_contract() {
    // Passkey RP IDs use capacity 64; do not hash a trimmed three-byte array.
    let mut rp = [0; 64];
    rp[0] = 97;
    rp[1] = 98;
    let expected = poseidon2_hash([2, poseidon2_hash_bytes(rp)]);
    let mut padded = rp;
    padded[63] = 255;
    assert_eq(crate::bytes::prefix_hash(padded, 2), expected);
    let mut bounded: BoundedVec<u8, 64> = BoundedVec::new();
    bounded.push(97);
    bounded.push(98);
    assert_eq(crate::bytes::bytes_hash(bounded), expected);
    assert(crate::bytes::prefix_hash(rp, 3) != expected);
    assert_eq(crate::bytes::prefix_hash([255; 64], 0), poseidon2_hash([0, poseidon2_hash_bytes([0; 64])]));
    assert_eq(crate::bytes::prefix_hash([255; 64], 64), poseidon2_hash([64, poseidon2_hash_bytes([255; 64])]));
    assert(crate::bytes::prefix_hash([0; 128], 0) != crate::bytes::prefix_hash([0; 64], 0));
}

#[test(should_fail_with = "Length exceeds capacity")]
fn byte_prefix_rejects_length_past_capacity() {
    let _ = crate::bytes::prefix_hash([0; 64], 65);
}

#[test]
fn bytes_hash_ignores_storage_after_the_length() {
    let a: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 0, 0, 0, 0, 0], 3);
    let b: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 9, 9, 9, 9, 9], 3);
    assert_eq(crate::bytes::bytes_hash(a), crate::bytes::bytes_hash(b));
    let c: BoundedVec<u8, 8> = BoundedVec::from_parts([1, 2, 3, 0, 0, 0, 0, 0], 4);
    assert(crate::bytes::bytes_hash(a) != crate::bytes::bytes_hash(c));
}

#[test]
fn decimal_u64_parses_seconds_and_milliseconds() {
    assert_eq(crate::bytes::decimal_u64(BoundedVec::from_array("1900000000".as_bytes())), 1900000000);
    assert_eq(crate::bytes::decimal_u64(BoundedVec::from_array("4000000000000".as_bytes())), 4000000000000);
    assert_eq(crate::bytes::decimal_u64(BoundedVec::new()), 0);
}
