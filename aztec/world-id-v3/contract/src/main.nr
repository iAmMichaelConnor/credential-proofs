// Verify a World ID 3 claim under an expiring root snapshot and consume its action nullifier.
use aztec::macros::aztec;

#[aztec]
pub contract WorldId3Gate {
    use aztec::context::{PrivateContext, PublicContext};
    use aztec::macros::{functions::{external, initializer}, storage::storage};
    use aztec::protocol::traits::ToField;
    use aztec::state_vars::PublicImmutable;

    #[storage]
    struct Storage<Context> {
        inner_key: PublicImmutable<Field, Context>,
        root: PublicImmutable<Field, Context>,
        root_valid_until: PublicImmutable<u64, Context>,
        external_nullifier: PublicImmutable<Field, Context>,
    }

    // The deployer authenticates this root/key/action snapshot. A real root
    // synchronization policy can replace this bounded immutable snapshot.
    // No server response or proof-supplied root grants its own authorization.
    #[external("public")]
    #[initializer]
    fn constructor(inner_key: Field, root: Field, valid_until: u64, external_nullifier: Field) {
        initialize_snapshot(
            self.context,
            inner_key,
            root,
            valid_until,
            external_nullifier,
        );
    }

    #[external("private")]
    fn claim(
        key: [[u128; 3]; 24],
        proof: [[u128; 3]; 8],
        hints: [Field; 2815],
        public_inputs: [Field; 4],
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
    pub fn initialize_snapshot(
        context: PublicContext,
        inner_key: Field,
        root: Field,
        valid_until: u64,
        external_nullifier: Field,
    ) {
        assert(inner_key != 0, "Zero World ID key");
        let storage = Storage::init(context);
        storage.inner_key.initialize(inner_key);
        storage.root.initialize(root);
        storage.root_valid_until.initialize(valid_until);
        storage.external_nullifier.initialize(external_nullifier);
    }

    // The claim under the stored snapshot (inner_key, root, until, action).
    #[contract_library_method]
    pub fn verify_claim(
        context: &mut PrivateContext,
        key: [[u128; 3]; 24],
        proof: [[u128; 3]; 8],
        hints: [Field; 2815],
        public_inputs: [Field; 4],
        beneficiary: Field,
        nonce: Field,
    ) -> Field {
        claim_with(
            context,
            public_inputs,
            beneficiary,
            nonce,
            |inputs, authorized_key| uniqueness::groth16::verify(
                uniqueness::groth16::decode_key::<4>(key),
                inputs,
                proof,
                uniqueness::groth16::decode_hints::<4>(hints),
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
        public_inputs: [Field; 4],
        beneficiary: Field,
        nonce: Field,
        verify: fn[Env]([Field; 4], Field) -> (),
    ) -> Field {
        let storage = Storage::init(context);
        check_root_window(context, storage.root_valid_until.read());
        verify(public_inputs, storage.inner_key.read());
        consume_claim(
            context,
            storage.root.read(),
            storage.external_nullifier.read(),
            public_inputs,
            beneficiary,
            nonce,
        )
    }

    // claim_with's steps before and after proof verification.
    #[contract_library_method]
    pub fn check_root_window(context: &mut PrivateContext, until: u64) {
        assert(context.get_anchor_block_header().timestamp() <= until, "Root policy expired");
        // Bound inclusion time, not just the historical anchor block time.
        context.set_expiration_timestamp(until);
    }

    #[contract_library_method]
    pub fn consume_claim(
        context: &mut PrivateContext,
        root: Field,
        action: Field,
        public_inputs: [Field; 4],
        beneficiary: Field,
        nonce: Field,
    ) -> Field {
        let signal_context =
            [context.chain_id(), context.version(), context.this_address().to_field(), action, beneficiary, nonce];
        let nullifier = uniqueness::check_semaphore(public_inputs, root, action, signal_context);
        // The private kernel siloes this value by contract address. The base
        // rollup's indexed-tree insertion rejects a value already in the
        // nullifier tree or repeated in the same transaction; the private
        // kernel does not. Uniqueness therefore holds per gate contract. The
        // nullifier takes the caller's phase: if a non-revertible effect
        // depends on this claim, call the gate before end_setup
        // (docs/world-id.md "What a claim establishes").
        context.push_nullifier_unsafe(nullifier);
        beneficiary
    }
}
