//! World ID uniqueness policy: `check_semaphore` (World ID 3) and
//! `check_nullifier` with a `NullifierPolicy` built by
//! `NullifierPolicy::from_fields` (World ID 4; values outside the policy domain
//! are rejected, and `check_nullifier` validates again). `groth16::verify`
//! delegates proof verification to groth16-verifier's `runtime_verifier::verify`.
//! Trusted keys, roots, application policy and nullifier emission are the
//! application's; see `docs/world-id.md`.
pub mod groth16;
mod benchmarks;
use poseidon::poseidon2::Poseidon2;
pub global DOMAIN: Field = 0x574f524c445f49445f415a5445435f5631;

// These are application policy checks, not proof verification. Every policy
// value must come from authenticated state/configuration, not prover advice.
// Protocol source: world-id-contracts@f959f725 and world-id-protocol@46f6b43.
pub use common::signal::signal_hash;

pub fn check_semaphore(
    inputs: [Field; 4],
    approved_root: Field,
    external_nullifier: Field,
    context: [Field; 6],
) -> Field {
    assert(inputs[0] == approved_root, "Unapproved root");
    assert(inputs[3] == external_nullifier, "Wrong external nullifier");
    assert(inputs[2] == signal_hash(context), "Wrong signal binding");
    // Root/beneficiary/nonce must NOT enter this hash: changing them must not
    // permit using the same per-action identity nullifier a second time.
    Poseidon2::hash([DOMAIN + 1, 3, inputs[3], inputs[1]], 4)
}

pub struct NullifierPolicy {
    pub root: Field,
    pub issuer_schema_id: u64,
    pub issuer_key: [Field; 2],
    pub oprf_key: [Field; 2],
    pub rp_id: u64,
    pub action: Field,
    pub tree_depth: u64,
    pub min_expiry: u64,
    pub min_genesis: u64,
}

// Upstream BinaryMerkleRoot(30) (world-id-protocol@46f6b43
// circom/merkle_tree/binary_merkle_root.circom:23-24) outputs 0 for every
// depth outside [0, 30] and says the depth must be enforced outside the
// circuit. Upstream WorldIDVerifier takes the depth from the registry and the
// root from isValidRoot, which never accepts 0. A policy must do the same.
pub global WORLD_ID4_MAX_TREE_DEPTH: u64 = 30;

impl NullifierPolicy {
    // Policy domain. Integer fields are u64 by type. Every check here is a
    // precondition of the upstream relation, not prover advice.
    pub fn validate(self) {
        assert(self.root != 0, "Zero root");
        assert(self.tree_depth <= WORLD_ID4_MAX_TREE_DEPTH, "Tree depth range");
        assert((self.issuer_key[0] != 0) & (self.issuer_key[1] != 0), "Unregistered issuer");
        // WorldIDVerifierV2: uniqueness actions have top byte 0x00.
        assert(self.action.to_be_bytes::<32>()[0] == 0, "Uniqueness action range");
    }

    // Decode the 11-field storage layout [root, issuer_schema_id,
    // issuer_key[2], oprf_key[2], rp_id, action, tree_depth, min_expiry,
    // min_genesis]. Integer fields must be canonical u64 values: a Field cast
    // alone would truncate p - 1 or 2^64 to an unrelated integer.
    pub fn from_fields(p: [Field; 11]) -> Self {
        let issuer = p[1] as u64;
        let rp = p[6] as u64;
        let depth = p[8] as u64;
        let minimum = p[9] as u64;
        let genesis = p[10] as u64;
        assert(
            (p[1] == issuer as Field)
                & (p[6] == rp as Field)
                & (p[8] == depth as Field)
                & (p[9] == minimum as Field)
                & (p[10] == genesis as Field),
            "Policy integer range",
        );
        let policy = NullifierPolicy {
            root: p[0],
            issuer_schema_id: issuer,
            issuer_key: [p[2], p[3]],
            oprf_key: [p[4], p[5]],
            rp_id: rp,
            action: p[7],
            tree_depth: depth,
            min_expiry: minimum,
            min_genesis: genesis,
        };
        policy.validate();
        policy
    }
}

// Fifteen public inputs in the exact order of WorldIDVerifier.sol.
// This function handles uniqueness only. Sessions have distinct semantics.
pub fn check_nullifier(
    inputs: [Field; 15],
    policy: NullifierPolicy,
    context: [Field; 6],
    now: u64,
) -> (Field, u64) {
    policy.validate();
    assert(inputs[1] == policy.issuer_schema_id as Field, "Wrong issuer");
    assert(
        (inputs[2] == policy.issuer_key[0]) & (inputs[3] == policy.issuer_key[1]),
        "Wrong issuer key",
    );
    let expiry = inputs[4] as u64;
    assert(inputs[4] == expiry as Field, "Expiration range");
    // Strict: expires_at_min must not be before the anchor time. The upstream
    // default request flow sets expires_at_min to the request time, which is
    // already past at inclusion; requests for this gate must set it explicitly.
    assert((expiry >= now) & (expiry >= policy.min_expiry), "Credential expiration bound too old");
    // Upstream LessEqThan(64)([gmin, g]) means gmin <= g only when gmin < 2^64:
    // gmin in [p - 2^64 + g + 1, p) also satisfies it. inputs[5] is prover
    // supplied here, so it must be a canonical u64 before the comparison.
    let genesis = inputs[5] as u64;
    assert(inputs[5] == genesis as Field, "Genesis range");
    assert(genesis >= policy.min_genesis, "Credential genesis bound too old");
    assert(inputs[6] == policy.root, "Unapproved root");
    assert(inputs[7] == policy.tree_depth as Field, "Wrong tree depth");
    assert(inputs[8] == policy.rp_id as Field, "Wrong relying party");
    assert(inputs[9] == policy.action, "Wrong action");
    assert(
        (inputs[10] == policy.oprf_key[0]) & (inputs[11] == policy.oprf_key[1]),
        "Wrong OPRF key",
    );
    assert(inputs[12] == signal_hash(context), "Wrong signal binding");
    assert(inputs[13] == context[5], "Wrong nonce");
    assert(inputs[14] == 0, "Session proofs require a separate policy");
    // The upstream nullifier depends on the account (leaf index), rp_id,
    // action and OPRF key only (world-id-protocol@46f6b43
    // circom/client_side_proofs/oprf_nullifier.circom:114, :172-173), not on
    // the credential issuer. issuer_schema_id must not enter this hash either: a
    // consumer that accepts several issuers would otherwise allow one claim
    // per issuer for the same account and action. The issuer is still
    // checked above. Root, beneficiary and nonce stay out for the same reason
    // as in check_semaphore. Poseidon2 binds the five-field input length.
    // Changing the encoding of a live gate would let every account claim again.
    (Poseidon2::hash([DOMAIN + 1, 4, inputs[8], inputs[9], inputs[0]], 5), expiry)
}

// Test inputs pass through `std::hint::black_box` so that the compiler cannot
// fold the constrained checks away.
fn semaphore(inputs: [Field; 4], root: Field, action: Field, context: [Field; 6]) -> Field {
    check_semaphore(
        std::hint::black_box(inputs),
        std::hint::black_box(root),
        std::hint::black_box(action),
        std::hint::black_box(context),
    )
}
fn nullifier(
    inputs: [Field; 15],
    policy: NullifierPolicy,
    context: [Field; 6],
    now: u64,
) -> (Field, u64) {
    check_nullifier(
        std::hint::black_box(inputs),
        std::hint::black_box(policy),
        std::hint::black_box(context),
        std::hint::black_box(now),
    )
}
fn decode(fields: [Field; 11]) -> NullifierPolicy {
    NullifierPolicy::from_fields(std::hint::black_box(fields))
}
#[test]
fn signal_matches_typescript() {
    assert(
        signal_hash(std::hint::black_box([1, 1, 2, 3, 4, 5]))
            == 369385091653396019721806165947400015925512543297130582838346232286026425085,
    );
}

#[test]
fn zero_nullifier_is_valid_and_root_independent() {
    let context = [1, 1, 2, 3, 4, 5];
    let signal = signal_hash(context);
    let a = semaphore([7, 0, signal, 8], 7, 8, context);
    let b = semaphore([9, 0, signal, 8], 9, 8, context);
    assert(a == b);
}

#[test(should_fail_with = "Wrong signal binding")]
fn changed_beneficiary_fails() {
    let signal = signal_hash([1, 1, 2, 3, 4, 5]);
    let _ = semaphore([7, 0, signal, 8], 7, 8, [1, 1, 2, 3, 9, 5]);
}

fn test_policy() -> NullifierPolicy {
    NullifierPolicy {
        root: 7,
        issuer_schema_id: 1,
        issuer_key: [2, 3],
        oprf_key: [4, 5],
        rp_id: 6,
        action: 7,
        tree_depth: 30,
        min_expiry: 50,
        min_genesis: 9,
    }
}
fn test_inputs() -> [Field; 15] {
    [0, 1, 2, 3, 100, 9, 7, 30, 6, 7, 4, 5, signal_hash([1, 1, 2, 3, 4, 5]), 5, 0]
}
#[test]
fn nullifier_zero_and_equal_freshness_bound_are_valid() {
    let (a, expiry) = nullifier(test_inputs(), test_policy(), [1, 1, 2, 3, 4, 5], 100);
    assert(expiry == 100);
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[6] = 8;
    policy.root = 8;
    let (b, _) = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
    assert(a == b);
}
// The upstream nullifier is issuer-independent. Two policies that differ
// only in the accepted issuer must give the same Aztec nullifier for the same
// World ID nullifier, so a multi-issuer consumer allows one claim per account.
#[test]
fn nullifier_is_issuer_independent() {
    let (a, _) = nullifier(test_inputs(), test_policy(), [1, 1, 2, 3, 4, 5], 100);
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[1] = 2;
    inputs[2] = 12;
    inputs[3] = 13;
    policy.issuer_schema_id = 2;
    policy.issuer_key = [12, 13];
    let (b, _) = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
    assert(a == b);
}
// The nullifier still separates relying parties, actions and identities.
#[test]
fn nullifier_separates_rp_action_and_identity() {
    let (a, _) = nullifier(test_inputs(), test_policy(), [1, 1, 2, 3, 4, 5], 100);
    let mut inputs = test_inputs();
    inputs[0] = 1;
    let (b, _) = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
    assert(a != b);
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[8] = 16;
    policy.rp_id = 16;
    let (c, _) = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
    assert(a != c);
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    let context = [1, 1, 2, 17, 4, 5];
    inputs[9] = 17;
    inputs[12] = signal_hash(context);
    policy.action = 17;
    let (d, _) = nullifier(inputs, policy, context, 100);
    assert(a != d);
}
// The issuer check stays: a credential from an issuer outside the policy fails.
#[test(should_fail_with = "Wrong issuer")]
fn nullifier_other_issuer_is_rejected() {
    let mut inputs = test_inputs();
    inputs[1] = 2;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
// Upstream LessEqThan(64) accepts gmin = p - 1 for every credential genesis,
// so inputs[5] = p - 1 would bypass every min_genesis. It is rejected.
#[test(should_fail_with = "Genesis range")]
fn genesis_field_alias_p_minus_1_is_rejected() {
    let mut inputs = test_inputs();
    inputs[5] = -1;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Genesis range")]
fn genesis_two_to_64_is_rejected() {
    let mut inputs = test_inputs();
    inputs[5] = 0x10000000000000000;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Genesis range")]
fn genesis_upper_wrap_window_is_rejected() {
    // p - 2^64 + g + 1 with g = 9: the lowest value upstream LessEqThan(64)
    // accepts in the wrapped window for a credential with genesis 9.
    let mut inputs = test_inputs();
    inputs[5] = -0x10000000000000000 + 10;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
#[test]
fn genesis_u64_boundaries_are_valid() {
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[5] = 0xffffffffffffffff;
    policy.min_genesis = 0xffffffffffffffff;
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
    inputs[5] = 0;
    policy.min_genesis = 0;
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
    inputs[5] = 10;
    policy.min_genesis = 9;
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Credential genesis bound too old")]
fn older_genesis_is_rejected() {
    let mut inputs = test_inputs();
    inputs[5] = 8;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
// The upstream default request sets expires_at_min to the request time,
// which is before the anchor time at inclusion. The strict policy rejects it.
#[test(should_fail_with = "Credential expiration bound too old")]
fn default_request_flow_expiry_before_anchor_is_rejected() {
    let mut inputs = test_inputs();
    inputs[4] = 99;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Credential expiration bound too old")]
fn expiry_below_policy_minimum_is_rejected() {
    let mut policy = test_policy();
    policy.min_expiry = 101;
    let _ = nullifier(test_inputs(), policy, [1, 1, 2, 3, 4, 5], 100);
}
fn test_fields() -> [Field; 11] {
    [7, 1, 2, 3, 4, 5, 6, 7, 30, 50, 9]
}
#[test]
fn policy_fields_decode_and_boundaries_are_valid() {
    let policy = decode(test_fields());
    let _ = nullifier(test_inputs(), policy, [1, 1, 2, 3, 4, 5], 100);
    let mut p = test_fields();
    p[1] = 0xffffffffffffffff;
    p[6] = 0xffffffffffffffff;
    p[8] = 0;
    p[9] = 0xffffffffffffffff;
    p[10] = 0xffffffffffffffff;
    p[7] = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    let _ = decode(p);
}
// A deployer must not be able to store min_genesis = p - 1 (or any
// non-u64 value) and so rely on the wrapped upstream comparison.
#[test(should_fail_with = "Policy integer range")]
fn policy_min_genesis_p_minus_1_is_rejected() {
    let mut p = test_fields();
    p[10] = -1;
    let _ = decode(p);
}
#[test(should_fail_with = "Policy integer range")]
fn policy_min_genesis_two_to_64_is_rejected() {
    let mut p = test_fields();
    p[10] = 0x10000000000000000;
    let _ = decode(p);
}
#[test(should_fail_with = "Policy integer range")]
fn policy_min_expiry_alias_is_rejected() {
    let mut p = test_fields();
    p[9] = -1;
    let _ = decode(p);
}
#[test(should_fail_with = "Policy integer range")]
fn policy_issuer_alias_is_rejected() {
    let mut p = test_fields();
    p[1] = 0x10000000000000001;
    let _ = decode(p);
}
#[test(should_fail_with = "Policy integer range")]
fn policy_rp_alias_is_rejected() {
    let mut p = test_fields();
    p[6] = -1;
    let _ = decode(p);
}
// Root 0 with a depth outside [0, 30] removes registry membership
// upstream. Each half is rejected on its own.
#[test(should_fail_with = "Zero root")]
fn policy_zero_root_is_rejected() {
    let mut p = test_fields();
    p[0] = 0;
    let _ = decode(p);
}
#[test(should_fail_with = "Tree depth range")]
fn policy_tree_depth_31_is_rejected() {
    let mut p = test_fields();
    p[8] = 31;
    let _ = decode(p);
}
#[test(should_fail_with = "Policy integer range")]
fn policy_tree_depth_alias_is_rejected() {
    let mut p = test_fields();
    p[8] = -1;
    let _ = decode(p);
}
#[test(should_fail_with = "Zero root")]
fn direct_policy_zero_root_is_rejected() {
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[6] = 0;
    policy.root = 0;
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Tree depth range")]
fn direct_policy_tree_depth_31_is_rejected() {
    let mut inputs = test_inputs();
    let mut policy = test_policy();
    inputs[7] = 31;
    policy.tree_depth = 31;
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, 5], 100);
}
// Each half of the issuer key is checked on its own.
#[test(should_fail_with = "Unregistered issuer")]
fn policy_zero_issuer_key_0_is_rejected() {
    let mut p = test_fields();
    p[2] = 0;
    let _ = decode(p);
}
#[test(should_fail_with = "Unregistered issuer")]
fn policy_zero_issuer_key_1_is_rejected() {
    let mut p = test_fields();
    p[3] = 0;
    let _ = decode(p);
}
// WorldIDVerifierV2 accepts only top byte 0x00 for uniqueness; 0x01 is
// unassigned and 0x02 is the session prefix.
#[test(should_fail_with = "Uniqueness action range")]
fn action_prefix_01_is_rejected() {
    let mut p = test_fields();
    p[7] = 0x0100000000000000000000000000000000000000000000000000000000000007;
    let _ = decode(p);
}
#[test(should_fail_with = "Uniqueness action range")]
fn action_session_prefix_02_is_rejected() {
    let mut p = test_fields();
    p[7] = 0x0200000000000000000000000000000000000000000000000000000000000007;
    let _ = decode(p);
}
#[test(should_fail_with = "Uniqueness action range")]
fn action_top_byte_alias_is_rejected() {
    let mut p = test_fields();
    p[7] = -1;
    let _ = decode(p);
}
// The upstream vector (fixtures/world-id/nullifier-v4.json,
// from Verifier.t.sol testVerifyNullifier) is a raw Groth16 vector. Its action
// top byte is 0x15, so the V2 uniqueness policy rejects it.
#[test(should_fail_with = "Uniqueness action range")]
fn upstream_raw_v4_vector_fails_uniqueness_policy() {
    let inputs = [
        0x1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702,
        0x1,
        0x252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81,
        0x230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5,
        0x699cfa47,
        0x0,
        0xaf727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853,
        0x1e,
        0x1a6ccf8f70e5de68,
        0x15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f,
        0xac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d,
        0x187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be,
        0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f,
        0x18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e,
        0x0,
    ];
    let policy = NullifierPolicy {
        root: inputs[6],
        issuer_schema_id: 1,
        issuer_key: [inputs[2], inputs[3]],
        oprf_key: [inputs[10], inputs[11]],
        rp_id: 0x1a6ccf8f70e5de68,
        action: inputs[9],
        tree_depth: 30,
        min_expiry: 0,
        min_genesis: 0,
    };
    let _ = nullifier(inputs, policy, [1, 1, 2, 3, 4, inputs[13]], 0x699cfa47);
}
#[test(should_fail_with = "Expiration range")]
fn expiration_integer_alias_is_rejected() {
    let mut inputs = test_inputs();
    inputs[4] = 0x10000000000000064;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
#[test(should_fail_with = "Session proofs require a separate policy")]
fn session_is_not_a_uniqueness_claim() {
    let mut inputs = test_inputs();
    inputs[14] = 1;
    let _ = nullifier(inputs, test_policy(), [1, 1, 2, 3, 4, 5], 100);
}
// min_genesis is u64 by type, so the largest policy value is 2^64 - 1. A
// smaller credential genesis fails it.
#[test(should_fail_with = "Credential genesis bound too old")]
fn smaller_canonical_genesis_is_rejected() {
    let mut policy = test_policy();
    policy.min_genesis = 0xffffffffffffffff;
    let _ = nullifier(test_inputs(), policy, [1, 1, 2, 3, 4, 5], 100);
}
