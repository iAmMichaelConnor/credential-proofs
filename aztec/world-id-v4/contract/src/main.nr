// Verify a World ID 4 uniqueness claim under the configured issuer, root and freshness policy.
use aztec::macros::aztec;
#[aztec]
pub contract WorldId4Gate {
    use aztec::context::{PrivateContext, PublicContext};
    use aztec::macros::{functions::{external, initializer}, storage::storage};
    use aztec::protocol::traits::ToField;
    use aztec::state_vars::PublicImmutable;
    use aztec::test::helpers::test_environment::{PrivateContextOptions, TestEnvironment};
    use uniqueness::NullifierPolicy;
    #[storage]
    struct Storage<Context> {
        inner_key: PublicImmutable<Field, Context>,
        // Explicit public configuration: root, issuer ID/key, OPRF key, RP,
        // action, depth, expiry/genesis bounds. This is an authenticated snapshot.
        policy: PublicImmutable<[Field; 11], Context>,
        root_valid_until: PublicImmutable<u64, Context>,
    }
    #[external("public")]
    #[initializer]
    fn constructor(inner_key: Field, policy: [Field; 11], valid_until: u64) {
        initialize_configuration(self.context, inner_key, policy, valid_until);
    }
    #[external("private")]
    fn claim(
        key: [[u128; 3]; 46],
        proof: [[u128; 3]; 8],
        hints: [Field; 2859],
        public_inputs: [Field; 15],
        beneficiary: Field,
        nonce: Field,
    ) -> Field {
        verify_claim(
            self.context,
            key,
            proof,
            hints,
            public_inputs,
            beneficiary,
            nonce,
        )
    }

    // The constructor's body.
    #[contract_library_method]
    pub fn initialize_configuration(context: PublicContext, inner_key: Field, policy: [Field; 11], valid_until: u64) {
        check_configuration(inner_key, policy);
        // valid_until is not capped here: the nullifier is siloed to this
        // contract, so forcing short-lived gates would force successor gates
        // with empty nullifier sets. See docs/world-id.md "Root snapshot age".
        let storage = Storage::init(context);
        storage.inner_key.initialize(inner_key);
        storage.policy.initialize(policy);
        storage.root_valid_until.initialize(valid_until);
    }

    // The constructor's checks.
    #[contract_library_method]
    pub fn check_configuration(inner_key: Field, policy: [Field; 11]) {
        assert(inner_key != 0, "Zero World ID key");
        // Reject a policy outside its domain at deployment, not only per claim.
        let _ = NullifierPolicy::from_fields(policy);
    }

    // The claim under the stored configuration (inner_key, policy, until).
    #[contract_library_method]
    pub fn verify_claim(
        context: &mut PrivateContext,
        key: [[u128; 3]; 46],
        proof: [[u128; 3]; 8],
        hints: [Field; 2859],
        public_inputs: [Field; 15],
        beneficiary: Field,
        nonce: Field,
    ) -> Field {
        claim_with(
            context,
            public_inputs,
            beneficiary,
            nonce,
            |inputs, authorized_key| uniqueness::groth16::verify(
                uniqueness::groth16::decode_key::<15>(key),
                inputs,
                proof,
                uniqueness::groth16::decode_hints::<15>(hints),
                authorized_key,
            ),
        )
    }

    // verify_claim's steps in order, with the Groth16 verification passed in as
    // `verify(public_inputs, authorized_key)`. verify_claim passes the real
    // verifier; tests pass a stand-in so that they run the whole composition,
    // storage reads included, without compiling the verifier.
    #[contract_library_method]
    pub fn claim_with<Env>(
        context: &mut PrivateContext,
        public_inputs: [Field; 15],
        beneficiary: Field,
        nonce: Field,
        verify: fn[Env]([Field; 15], Field) -> (),
    ) -> Field {
        let storage = Storage::init(context);
        let policy = NullifierPolicy::from_fields(storage.policy.read());
        let until = storage.root_valid_until.read();
        let now = claim_time(context, until);
        verify(public_inputs, storage.inner_key.read());
        consume_claim(
            context,
            policy,
            until,
            now,
            public_inputs,
            beneficiary,
            nonce,
        )
    }

    // claim_with's steps before and after proof verification.
    #[contract_library_method]
    pub fn claim_time(context: &mut PrivateContext, until: u64) -> u64 {
        let now = claim_anchor_timestamp(context);
        assert(now <= until, "Root policy expired");
        now
    }

    #[contract_library_method]
    pub fn consume_claim(
        context: &mut PrivateContext,
        policy: NullifierPolicy,
        until: u64,
        now: u64,
        public_inputs: [Field; 15],
        beneficiary: Field,
        nonce: Field,
    ) -> Field {
        let signal_context = [
            context.chain_id(),
            context.version(),
            context.this_address().to_field(),
            policy.action,
            beneficiary,
            nonce,
        ];
        let (nullifier, expiry) = uniqueness::check_nullifier(public_inputs, policy, signal_context, now);
        // The proof establishes private expires_at > public expiry. Limiting
        // transaction inclusion time to expiry prevents using an old anchor.
        set_claim_expiration(context, until, expiry);
        // Siloed by contract address; the base rollup, not the private kernel,
        // rejects duplicates. The nullifier takes the caller's phase; see
        // docs/world-id.md "What a claim establishes".
        context.push_nullifier_unsafe(nullifier);
        beneficiary
    }

    // Internal helpers keep these exact context effects observable in TXE tests.
    // The gate reads authenticated policy before calling either helper.
    #[contract_library_method]
    fn claim_anchor_timestamp(context: &mut PrivateContext) -> u64 {
        let anchor = context.get_anchor_block_header();
        // Block 1 can only anchor to genesis, where the rollup skips expiration.
        assert(anchor.block_number() != 0, "Genesis anchor");
        anchor.timestamp()
    }

    #[contract_library_method]
    fn set_claim_expiration(context: &mut PrivateContext, until: u64, expiry: u64) {
        context.set_expiration_timestamp(std::cmp::min(until, expiry));
    }

    #[test(should_fail_with = "Genesis anchor")]
    unconstrained fn rejects_genesis_anchor() {
        let env = TestEnvironment::new();
        env.private_context_opts(PrivateContextOptions::new().at_anchor_block_number(0), |context| {
            let _ = claim_anchor_timestamp(context);
        });
    }

    #[test]
    unconstrained fn accepts_non_genesis_anchor() {
        let env = TestEnvironment::new();
        env.mine_block();
        let now = env.last_block_timestamp();
        env.private_context(|context| { assert_eq(claim_anchor_timestamp(context), now); });
    }

    #[test]
    unconstrained fn expiration_is_capped_by_credential() {
        let env = TestEnvironment::new();
        env.mine_block();
        let now = env.last_block_timestamp();
        env.private_context(|context| {
            set_claim_expiration(context, now + 300, now + 200);
            assert_eq((*context).finish().expiration_timestamp, now + 200);
        });
    }

    #[test]
    unconstrained fn expiration_is_capped_by_root() {
        let env = TestEnvironment::new();
        env.mine_block();
        let now = env.last_block_timestamp();
        env.private_context(|context| {
            set_claim_expiration(context, now + 200, now + 300);
            assert_eq((*context).finish().expiration_timestamp, now + 200);
        });
    }

    #[test]
    unconstrained fn expiration_accepts_equal_bounds() {
        let env = TestEnvironment::new();
        env.mine_block();
        let now = env.last_block_timestamp();
        env.private_context(|context| {
            set_claim_expiration(context, now + 200, now + 200);
            assert_eq((*context).finish().expiration_timestamp, now + 200);
        });
    }
}
