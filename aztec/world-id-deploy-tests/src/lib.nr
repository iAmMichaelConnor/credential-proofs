// Deploy tests of the World ID gates: each test deploys a gate's compiled artifact from aztec/target (built by
// `scripts/test-world-id.sh --unconstrained-contracts`) and calls its entry points through TXE, so the arguments cross
// the ABI and the code that `#[initializer]` adds runs.
//
// They cover what the context tests in world-id-v3/tests and world-id-v4/tests cannot: that `constructor` stores each
// argument in the slot the claim reads, that a deployed gate cannot be initialised again, and that a claim at a gate
// deployed without its initializer fails. They make no successful claim: the saved proofs bind the fixed test address
// of the context tests, and a deployed gate's address derives from its class id, salt, initialisation hash and keys,
// so no deployment has that address. The forwarding of `claim`'s arguments is therefore not covered.
use aztec::{
    context::PublicContext,
    protocol::address::AztecAddress,
    state_vars::{PublicImmutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use world::WorldId3Gate;
use world4::WorldId4Gate;

global GATE3: str<28> = "@world_id3_gate/WorldId3Gate";
global GATE4: str<28> = "@world_id4_gate/WorldId4Gate";

// Distinct values, so that a constructor that swaps two of them stores a value in the wrong slot.
global INNER_KEY: Field = 11;
global ROOT: Field = 22;
global ACTION: Field = 33;
global VALID_UNTIL: u64 = 1900000000;

// [root, issuer_schema_id, issuer_key[2], oprf_key[2], rp_id, action, tree_depth, min_expiry, min_genesis]: a World ID
// 4 policy inside its domain.
fn policy() -> [Field; 11] {
    [7, 1, 2, 3, 4, 5, 6, 7, 30, 50, 9]
}

unconstrained fn read_field(env: TestEnvironment, gate: AztecAddress, slot: Field) -> Field {
    env.public_context_at(gate, |context| PublicImmutable::<Field, PublicContext>::new(context, slot).read())
}

unconstrained fn deploy3(env: &mut TestEnvironment) -> AztecAddress {
    let deployer = env.create_light_account();
    env.deploy(GATE3).with_public_initializer(
        deployer,
        WorldId3Gate::interface().constructor(INNER_KEY, ROOT, VALID_UNTIL, ACTION),
    )
}

unconstrained fn deploy4(env: &mut TestEnvironment) -> AztecAddress {
    let deployer = env.create_light_account();
    env.deploy(GATE4).with_public_initializer(
        deployer,
        WorldId4Gate::interface().constructor(INNER_KEY, policy(), VALID_UNTIL),
    )
}

#[test]
unconstrained fn world_id3_constructor_stores_each_argument() {
    let mut env = TestEnvironment::new();
    let gate = deploy3(&mut env);
    let layout = WorldId3Gate::storage_layout();
    assert_eq(read_field(env, gate, layout.inner_key.slot), INNER_KEY);
    assert_eq(read_field(env, gate, layout.root.slot), ROOT);
    assert_eq(read_field(env, gate, layout.external_nullifier.slot), ACTION);
    let until = env.public_context_at(gate, |context| {
        PublicImmutable::<u64, PublicContext>::new(context, layout.root_valid_until.slot).read()
    });
    assert_eq(until, VALID_UNTIL);
}

// A second call of the constructor, here to replace the root, fails the initialisation check: the address commits to
// the deployment's constructor arguments. (With the same arguments it fails on the storage's initialisation
// nullifiers instead.)
#[test(should_fail_with = "Initialization hash does not match")]
unconstrained fn world_id3_second_initialisation_rejected() {
    let mut env = TestEnvironment::new();
    let gate = deploy3(&mut env);
    let caller = env.create_light_account();
    env.call_public(caller, WorldId3Gate::at(gate).constructor(INNER_KEY, ROOT + 1, VALID_UNTIL, ACTION));
}

// A claim at a gate deployed without its initializer fails. Its arguments do not matter: the first storage read fails
// during execution, before TXE checks the read request of the initialisation check that `#[initializer]` adds.
#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn world_id3_claim_before_initialisation_rejected() {
    let mut env = TestEnvironment::new();
    let gate = env.deploy(GATE3).without_initializer();
    let caller = env.create_light_account();
    let _ = env.call_private(
        caller,
        WorldId3Gate::at(gate).claim(
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            13,
            17,
        ),
    );
}

#[test]
unconstrained fn world_id4_constructor_stores_each_argument() {
    let mut env = TestEnvironment::new();
    let gate = deploy4(&mut env);
    let layout = WorldId4Gate::storage_layout();
    assert_eq(read_field(env, gate, layout.inner_key.slot), INNER_KEY);
    let stored_policy = env.public_context_at(gate, |context| {
        PublicImmutable::<[Field; 11], PublicContext>::new(context, layout.policy.slot).read()
    });
    assert_eq(stored_policy, policy());
    let until = env.public_context_at(gate, |context| {
        PublicImmutable::<u64, PublicContext>::new(context, layout.root_valid_until.slot).read()
    });
    assert_eq(until, VALID_UNTIL);
}

#[test(should_fail_with = "Initialization hash does not match")]
unconstrained fn world_id4_second_initialisation_rejected() {
    let mut env = TestEnvironment::new();
    let gate = deploy4(&mut env);
    let caller = env.create_light_account();
    env.call_public(caller, WorldId4Gate::at(gate).constructor(INNER_KEY + 1, policy(), VALID_UNTIL));
}

#[test(should_fail_with = "Trying to read from uninitialized PublicImmutable")]
unconstrained fn world_id4_claim_before_initialisation_rejected() {
    let mut env = TestEnvironment::new();
    let gate = env.deploy(GATE4).without_initializer();
    let caller = env.create_light_account();
    let _ = env.call_private(
        caller,
        WorldId4Gate::at(gate).claim(
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            13,
            17,
        ),
    );
}
