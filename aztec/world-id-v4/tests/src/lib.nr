// WorldId4Gate's constructor body and claim logic in TXE contexts at the
// address the saved synthetic ceremony proof binds; no contract is compiled or
// deployed. Each claim test writes the gate's configuration with the
// constructor's body (`initialize_configuration`) in a public context at that
// address, then runs the function `claim` calls (or the composition it wraps)
// in a private context there, so the storage reads are the contract's own.
// Inline contract tests separately inspect anchor and expiration context
// effects.
//
// Compiling the Groth16 verifier to Brillig is far slower than compiling it
// to a circuit, so only the two tests that need the verifier run the whole
// claim (`verify_claim`), as constrained tests: they compile it to a circuit,
// as the contract does. The other tests run the same composition
// (`claim_with`) with a stand-in for the verification step, on the proof's
// public inputs.
mod fixture;
use aztec::context::{inputs::PrivateContextInputs, PrivateContext};
use aztec::protocol::{
    abis::{
        gas::Gas, gas_fees::GasFees, gas_settings::GasSettings,
        private_circuit_public_inputs::PrivateCircuitPublicInputs,
    },
    address::AztecAddress,
    constants::{MAX_PROCESSABLE_DA_GAS_PER_CHECKPOINT, MAX_PROCESSABLE_L2_GAS},
    traits::{Empty, FromField},
};
use aztec::test::helpers::{test_environment::TestEnvironment, txe_oracles};
use std::hint::black_box;
use world4::WorldId4Gate::{claim_with, initialize_configuration, verify_claim};

global KEY_HASH: Field = 11;
global VALID_UNTIL: u64 = 1900000000;

// The nullifier the saved proof's claim pushes, before the kernel siloes it.
global NULLIFIER: Field = 0x1acb8d8dd02f96f12f38547cd3aa3bcacefb659d128671c7c76007a3a915eb9f;

// [root, issuer_schema_id, issuer_key[2], oprf_key[2], rp_id, action,
// tree_depth, min_expiry, min_genesis]: a policy inside its domain.
fn policy() -> [Field; 11] {
    [7, 1, 2, 3, 4, 5, 6, 7, 30, 50, 9]
}

fn gate() -> AztecAddress {
    AztecAddress::from_field(fixture::ADDRESS)
}

unconstrained fn setup() -> TestEnvironment {
    let env = TestEnvironment::new();
    env.mine_block();
    env
}

// Writes the gate's configuration in env as the constructor does.
unconstrained fn configure(env: TestEnvironment, inner_key: Field, p: [Field; 11], until: u64) {
    env.public_context_at(gate(), |context| initialize_configuration(context, inner_key, p, until));
}

// A gate configured with the fixture's key hash, policy p and root snapshot end.
unconstrained fn configured(p: [Field; 11]) -> TestEnvironment {
    let env = setup();
    configure(env, fixture::KEY_HASH, p, fixture::VALID_UNTIL);
    env
}

// A gate configured with key hash `inner_key` and the fixture's policy, and its
// root snapshot end: close enough to the latest block that it, not the
// credential's expiry or the default transaction lifetime, bounds inclusion.
// The proof does not bind it.
unconstrained fn configured_near_until(inner_key: Field) -> (TestEnvironment, u64) {
    let env = setup();
    let until = env.last_block_timestamp() + 600;
    configure(env, inner_key, fixture::POLICY, until);
    (env, until)
}

// The context effects of an accepted claim: exactly the claim's nullifier, and
// inclusion bounded by `expiration`.
fn assert_claim_effects(effects: PrivateCircuitPublicInputs, expiration: u64) {
    assert_eq(effects.nullifiers.length, 1);
    assert_eq(effects.nullifiers.array[0].inner.value, NULLIFIER);
    assert_eq(effects.expiration_timestamp, expiration);
}

// The other policy-domain rejections are NullifierPolicy::from_fields tests in
// noir/world_id_uniqueness.
#[test(should_fail_with = "Zero World ID key")]
unconstrained fn rejects_zero_inner_key_at_deployment() {
    configure(TestEnvironment::new(), 0, policy(), VALID_UNTIL);
}

#[test(should_fail_with = "Zero root")]
unconstrained fn rejects_zero_root_at_deployment() {
    let mut p = policy();
    p[0] = 0;
    configure(TestEnvironment::new(), KEY_HASH, p, VALID_UNTIL);
}

// The fixture's configuration is written by every claim test below.
#[test]
unconstrained fn accepts_configuration_in_domain() {
    configure(TestEnvironment::new(), KEY_HASH, policy(), VALID_UNTIL);
}

// A private context at the gate, configured with key hash `inner_key`, as
// TestEnvironment::private_context_at opens one, for a constrained test, and
// the gate's root snapshot end. A claim cannot anchor to genesis.
unconstrained fn open_context(inner_key: Field) -> (PrivateContextInputs, u64) {
    let (_, until) = configured_near_until(inner_key);
    let inputs = txe_oracles::set_private_txe_context(
        Option::some(gate()),
        Option::none(),
        GasSettings::new(
            Gas::new(
                MAX_PROCESSABLE_DA_GAS_PER_CHECKPOINT,
                MAX_PROCESSABLE_L2_GAS,
            ),
            Gas::new(
                MAX_PROCESSABLE_DA_GAS_PER_CHECKPOINT / 8,
                MAX_PROCESSABLE_L2_GAS / 8,
            ),
            GasFees::empty(),
            GasFees::empty(),
        ),
    );
    (inputs, until)
}

// The saved proof's whole claim at a gate that pins the key hash `inner_key`.
fn full_claim(inner_key: Field) {
    // Safety: test setup; the context's inputs come from TXE.
    let (inputs, until) = unsafe { open_context(inner_key) };
    let mut context = PrivateContext::new(inputs, 0);
    let beneficiary = verify_claim(
        &mut context,
        black_box(fixture::KEY),
        black_box(fixture::PROOF),
        black_box(fixture::HINTS),
        black_box(fixture::PUBLIC_INPUTS),
        black_box(13),
        black_box(17),
    );
    assert_eq(beneficiary, 13);
    assert_claim_effects(context.finish(), until);
    // Safety: test teardown.
    unsafe { txe_oracles::set_top_level_txe_context() };
}

#[test]
fn accepts_real_oprf_claim() {
    full_claim(fixture::KEY_HASH);
}

// The gate compares the hash of the supplied Groth16 key with the stored one,
// so a valid proof under a key the deployer did not pin is refused.
#[test(should_fail_with = "Unauthorized World ID verification key")]
fn rejects_unpinned_verification_key() {
    full_claim(fixture::KEY_HASH + 1);
}

// The claim's composition at the gate in its context, the verification step
// accepting.
unconstrained fn claim_steps(context: &mut PrivateContext, beneficiary: Field, nonce: Field) -> Field {
    claim_with(
        context,
        fixture::PUBLIC_INPUTS,
        beneficiary,
        nonce,
        |_, _| {},
    )
}

unconstrained fn claim(env: TestEnvironment, beneficiary: Field, nonce: Field) -> Field {
    env.private_context_at(gate(), |context| claim_steps(context, beneficiary, nonce))
}

unconstrained fn claim_with_policy(p: [Field; 11]) {
    let _ = claim(configured(p), 13, 17);
}

// The composition verifies the proof's public inputs once, under the stored
// key hash, and has the effects of the whole claim.
#[test]
unconstrained fn claim_verifies_under_stored_key_once() {
    let (env, until) = configured_near_until(fixture::KEY_HASH);
    env.private_context_at(gate(), |context| {
        let verified = &mut 0;
        let beneficiary = claim_with(
            context,
            fixture::PUBLIC_INPUTS,
            13,
            17,
            |inputs, authorized_key| {
                assert_eq(inputs, fixture::PUBLIC_INPUTS);
                assert_eq(authorized_key, fixture::KEY_HASH);
                *verified += 1;
            },
        );
        assert_eq(beneficiary, 13);
        assert_eq(*verified, 1);
        assert_claim_effects((*context).finish(), until);
    });
}

// The verification step fails if it is reached: the root window is checked first.
#[test(should_fail_with = "Root policy expired")]
unconstrained fn rejects_expired_policy_before_proof_verification() {
    let env = configured(fixture::POLICY);
    env.mine_block_at(fixture::VALID_UNTIL + 1);
    let _ = env.private_context_at(gate(), |context| {
        claim_with(
            context,
            fixture::PUBLIC_INPUTS,
            13,
            17,
            |_, _| assert(false, "Proof verification reached"),
        )
    });
}

// Without the constructor's writes the claim's first storage read fails.
#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn rejects_claim_without_configuration() {
    let _ = claim(setup(), 13, 17);
}

#[test(should_fail_with = "Wrong signal binding")]
unconstrained fn rejects_changed_beneficiary() {
    let _ = claim(configured(fixture::POLICY), 14, 17);
}

#[test(should_fail_with = "Wrong signal binding")]
unconstrained fn rejects_changed_nonce() {
    let _ = claim(configured(fixture::POLICY), 13, 18);
}

// The second claim's nullifier is already in the tree when TXE mines its block.
#[test(should_fail_with = "Unable to insert values into tree NullifierTree")]
unconstrained fn rejects_repeated_use() {
    let env = configured(fixture::POLICY);
    assert_eq(claim(env, 13, 17), 13);
    let _ = claim(env, 13, 17);
}

// Both claims run in one private context. Each passes the gate's checks;
// TXE refuses the second push of the same siloed nullifier (the base rollup
// does on a network).
#[test(should_fail_with = "Duplicate siloed nullifier")]
unconstrained fn rejects_duplicate_nullifier_within_one_transaction() {
    let env = configured(fixture::POLICY);
    env.private_context_at(gate(), |context| {
        assert_eq(claim_steps(context, 13, 17), 13);
        assert_eq(claim_steps(context, 13, 17), 13);
    });
}

#[test(should_fail_with = "Wrong issuer")]
unconstrained fn rejects_wrong_issuer_after_proof() {
    let mut p = fixture::POLICY;
    p[1] = p[1] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Wrong issuer key")]
unconstrained fn rejects_wrong_issuer_key_after_proof() {
    let mut p = fixture::POLICY;
    p[2] = p[2] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Wrong OPRF key")]
unconstrained fn rejects_wrong_oprf_key_after_proof() {
    let mut p = fixture::POLICY;
    p[4] = p[4] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Unapproved root")]
unconstrained fn rejects_wrong_root_after_proof() {
    let mut p = fixture::POLICY;
    p[0] = p[0] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Wrong tree depth")]
unconstrained fn rejects_wrong_tree_depth_after_proof() {
    let mut p = fixture::POLICY;
    p[8] = p[8] - 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Wrong relying party")]
unconstrained fn rejects_wrong_relying_party_after_proof() {
    let mut p = fixture::POLICY;
    p[6] = p[6] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Wrong action")]
unconstrained fn rejects_wrong_action_after_proof() {
    let mut p = fixture::POLICY;
    p[7] = p[7] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Credential expiration bound too old")]
unconstrained fn rejects_wrong_expiry_minimum_after_proof() {
    let mut p = fixture::POLICY;
    p[9] = p[9] + 1;
    claim_with_policy(p);
}

#[test(should_fail_with = "Credential genesis bound too old")]
unconstrained fn rejects_wrong_genesis_minimum_after_proof() {
    let mut p = fixture::POLICY;
    p[10] = p[10] + 1;
    claim_with_policy(p);
}

// At the boundary the transaction must be included by the credential's expiry,
// which is also the anchor time.
#[test]
unconstrained fn accepts_credential_at_expiry_boundary() {
    let env = configured(fixture::POLICY);
    let expiry = fixture::PUBLIC_INPUTS[4] as u64;
    env.mine_block_at(expiry);
    env.private_context_at(gate(), |context| {
        assert_eq(claim_steps(context, 13, 17), 13);
        assert_claim_effects((*context).finish(), expiry);
    });
}

#[test(should_fail_with = "Credential expiration bound too old")]
unconstrained fn rejects_credential_after_expiry() {
    let env = configured(fixture::POLICY);
    env.mine_block_at(fixture::PUBLIC_INPUTS[4] as u64 + 1);
    let _ = claim(env, 13, 17);
}
