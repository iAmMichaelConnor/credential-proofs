// WorldId3Gate's claim logic in TXE contexts at the address the saved
// synthetic Semaphore proof binds; no contract is compiled or deployed. Each
// test writes the gate's snapshot with the constructor's body
// (`initialize_snapshot`) in a public context at that address, then runs the
// function `claim` calls (or the composition it wraps) in a private context
// there, so the storage reads are the contract's own.
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
use world::WorldId3Gate::{check_root_window, claim_with, initialize_snapshot, verify_claim};

// The nullifier the saved proof's claim pushes, before the kernel siloes it.
global NULLIFIER: Field = 0x04e3f451a5760e3ba8c10b0052c41fe4d6f6447f9fb5595cf1a719b65f8d9836;

fn gate() -> AztecAddress {
    AztecAddress::from_field(fixture::ADDRESS)
}

// A test environment whose gate storage holds the snapshot (inner_key, root,
// until, action), as the constructor writes it, and that snapshot's `until`:
// close enough to the latest block that it, not the default transaction
// lifetime, bounds inclusion. The proof does not bind `until`.
unconstrained fn configured(inner_key: Field, root: Field, action: Field) -> (TestEnvironment, u64) {
    let env = TestEnvironment::new();
    env.mine_block();
    let until = env.last_block_timestamp() + 600;
    env.public_context_at(gate(), |context| initialize_snapshot(context, inner_key, root, until, action));
    (env, until)
}

// The context effects of an accepted claim: exactly the claim's nullifier, and
// inclusion bounded by the root snapshot.
fn assert_claim_effects(effects: PrivateCircuitPublicInputs, until: u64) {
    assert_eq(effects.nullifiers.length, 1);
    assert_eq(effects.nullifiers.array[0].inner.value, NULLIFIER);
    assert_eq(effects.expiration_timestamp, until);
}

// A private context at the gate, configured with the pinned key hash
// `inner_key`, as TestEnvironment::private_context_at opens one, for a
// constrained test.
unconstrained fn open_context(inner_key: Field) -> (PrivateContextInputs, u64) {
    let (_, until) = configured(inner_key, fixture::ROOT, fixture::EXTERNAL_NULLIFIER);
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
fn accepts_real_semaphore_claim() {
    full_claim(fixture::KEY_HASH);
}

// The gate compares the hash of the supplied Groth16 key with the stored one,
// so a valid proof under a key the deployer did not pin is refused.
#[test(should_fail_with = "Unauthorized World ID verification key")]
fn rejects_unpinned_verification_key() {
    full_claim(fixture::KEY_HASH + 1);
}

// The claim at the gate in env with beneficiary and nonce 17, the
// verification step accepting.
unconstrained fn claim(env: TestEnvironment, beneficiary: Field) -> Field {
    env.private_context_at(gate(), |context| claim_with(context, fixture::PUBLIC_INPUTS, beneficiary, 17, |_, _| {}))
}

// The composition verifies the proof's public inputs once, under the stored
// key hash, and has the effects of the whole claim.
#[test]
unconstrained fn claim_verifies_under_stored_key_once() {
    let (env, until) = configured(
        fixture::KEY_HASH,
        fixture::ROOT,
        fixture::EXTERNAL_NULLIFIER,
    );
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

// Each rejection below names the check that the changed value fails.
#[test(should_fail_with = "Wrong signal binding")]
unconstrained fn rejects_changed_beneficiary() {
    let (env, _) = configured(
        fixture::KEY_HASH,
        fixture::ROOT,
        fixture::EXTERNAL_NULLIFIER,
    );
    let _ = claim(env, 14);
}

#[test(should_fail_with = "Unapproved root")]
unconstrained fn rejects_unapproved_root() {
    let (env, _) = configured(
        fixture::KEY_HASH,
        fixture::ROOT + 1,
        fixture::EXTERNAL_NULLIFIER,
    );
    let _ = claim(env, 13);
}

#[test(should_fail_with = "Wrong external nullifier")]
unconstrained fn rejects_different_action() {
    let (env, _) = configured(
        fixture::KEY_HASH,
        fixture::ROOT,
        fixture::EXTERNAL_NULLIFIER + 1,
    );
    let _ = claim(env, 13);
}

// The verification step fails if it is reached: the root window is checked first.
#[test(should_fail_with = "Root policy expired")]
unconstrained fn rejects_expired_policy_before_proof_verification() {
    let (env, until) = configured(
        fixture::KEY_HASH,
        fixture::ROOT,
        fixture::EXTERNAL_NULLIFIER,
    );
    env.mine_block_at(until + 1);
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

#[test]
unconstrained fn expiration_is_capped_by_root() {
    let env = TestEnvironment::new();
    env.mine_block();
    let now = env.last_block_timestamp();
    env.private_context(|context| {
        check_root_window(context, now + 200);
        assert_eq((*context).finish().expiration_timestamp, now + 200);
    });
}

// The first claim succeeds. The second satisfies the gate's checks and fails
// on the state effect: TXE refuses to insert the repeated nullifier when it
// mines the second context's block (the base rollup does on a network).
#[test(should_fail_with = "Unable to insert values into tree NullifierTree")]
unconstrained fn rejects_repeated_use() {
    let (env, _) = configured(
        fixture::KEY_HASH,
        fixture::ROOT,
        fixture::EXTERNAL_NULLIFIER,
    );
    assert_eq(claim(env, 13), 13);
    let _ = claim(env, 13);
}

// Without the constructor's writes the claim's first storage read fails.
#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn rejects_claim_without_snapshot() {
    let env = TestEnvironment::new();
    env.mine_block();
    let _ = claim(env, 13);
}

#[test(should_fail_with = "Zero World ID key")]
unconstrained fn rejects_zero_inner_key_at_deployment() {
    let _ = configured(0, fixture::ROOT, fixture::EXTERNAL_NULLIFIER);
}
