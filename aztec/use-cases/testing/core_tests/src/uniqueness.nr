use crate::{deploy_with_immutables, in_context, requested_expiry};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::TestEnvironment,
};
use uc_trust::{
    ALSO_COPY_HOLDER, ANCHOR_REGISTRY, Binding, caller_binding, caller_choice_binding, SET_BY_HOLDER, SET_BY_NONE,
    SET_BY_PROVER, SOURCE_PROOF_SYSTEM, terms_commitment, Trust, TrustPolicy,
};
use uc_uniqueness::{
    DOMAIN_UNIQUE_BINDING, DOMAIN_UNIQUE_TERMS, once, once_with_bound_terms, once_with_choice,
    once_with_choice_with_bound_terms, PERSON_NATIONAL_ID, PERSON_WORLD_ID_IDENTITY, UniquenessClaim,
    UniquenessEvidence, UniqueTerms,
};

global SCHEME: u32 = 9004;

global REGISTRY: Field = 0x7e9;

/// A dummy membership proof under a registry root. `set_by == HOLDER` models
/// a World ID-like proof that needs the holder's secret; `PROVER` models a
/// document-based proof whose signal any copy holder can choose.
pub struct DummyPersonProof {
    pub root: Field,
    pub secret: Field,
    pub signal: Field,
    pub issued_at: u64,
    pub set_by: u8,
    pub person_kind: u8,
}

impl UniquenessEvidence for DummyPersonProof {
    let SCHEME: u32 = 9004;

    fn verify(self, _context: &mut PrivateContext, _binding: Field) -> UniquenessClaim {
        UniquenessClaim {
            trust: Trust {
                source: SOURCE_PROOF_SYSTEM,
                issuer: REGISTRY,
                anchor_kind: ANCHOR_REGISTRY,
                anchor: self.root,
                finality: 0,
                also_authorised: if self.set_by == SET_BY_HOLDER {
                    0
                } else {
                    ALSO_COPY_HOLDER
                },
            },
            person: poseidon2_hash([self.secret]),
            person_kind: self.person_kind,
            binding: Binding { value: self.signal, set_by: self.set_by },
            issued_at: self.issued_at,
        }
    }
}

fn terms() -> UniqueTerms {
    UniqueTerms {
        accepted: TrustPolicy {
            source: SOURCE_PROOF_SYSTEM,
            issuer: REGISTRY,
            anchor_kind: ANCHOR_REGISTRY,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        person_kind: PERSON_WORLD_ID_IDENTITY,
        max_age: 3600,
        allow_undated: false,
        allow_unbound: false,
        scope: 1,
    }
}

/// Acts once for the person `secret` and returns the requested inclusion
/// expiry. `undated` gives the proof no time; `SET_BY_NONE` gives it no
/// signal. With `at`, the public `once` runs at that deployed contract;
/// without it, `once_with_bound_terms` runs at the TXE default address.
unconstrained fn act_opts(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: UniqueTerms,
    secret: Field,
    age: u64,
    undated: bool,
    set_by: u8,
) -> u64 {
    let now = env.last_block_timestamp();
    in_context(
        env,
        at,
        |context| {
            let binding = caller_binding(
                DOMAIN_UNIQUE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
            );
            let proof = DummyPersonProof {
                root: 1,
                secret,
                signal: if set_by == SET_BY_NONE { 0 } else { binding },
                issued_at: if undated { 0 } else { now - age },
                set_by,
                person_kind: PERSON_WORLD_ID_IDENTITY,
            };
            let _ = if at.is_some() {
                once(context, terms, proof)
            } else {
                once_with_bound_terms(context, terms, proof)
            };
            requested_expiry(context)
        },
    )
}

unconstrained fn act(env: TestEnvironment, secret: Field, root: Field, age: u64, kind: u8) {
    let now = env.last_block_timestamp();
    env.private_context(|context| {
        let binding = caller_binding(
            DOMAIN_UNIQUE_BINDING,
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
        );
        let proof = DummyPersonProof {
            root,
            secret,
            signal: binding,
            issued_at: now - age,
            set_by: SET_BY_HOLDER,
            person_kind: kind,
        };
        let _ = once_with_bound_terms(context, terms(), proof);
    });
}

unconstrained fn act_choice_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: UniqueTerms,
    choice: Field,
    set_by: u8,
) {
    let now = env.last_block_timestamp();
    in_context(
        env,
        at,
        |context| {
            let binding = caller_choice_binding(
                DOMAIN_UNIQUE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                choice,
            );
            let proof = DummyPersonProof {
                root: 1,
                secret: 3,
                signal: binding,
                issued_at: now - 10,
                set_by,
                person_kind: PERSON_WORLD_ID_IDENTITY,
            };
            let _ = if at.is_some() {
                once_with_choice(context, terms, proof, choice)
            } else {
                once_with_choice_with_bound_terms(context, terms, proof, choice)
            };
        },
    );
}

unconstrained fn act_choice(env: TestEnvironment, choice: Field, set_by: u8) {
    act_choice_at(env, Option::none(), terms(), choice, set_by);
}

unconstrained fn deploy_unique(env: &mut TestEnvironment, terms: UniqueTerms) -> AztecAddress {
    deploy_with_immutables(
        env,
        terms_commitment(DOMAIN_UNIQUE_TERMS, SCHEME as Field, terms.hash()),
    )
}

#[test]
unconstrained fn unique_valid_accepted() {
    let env = TestEnvironment::new();
    act(env, 3, 1, 10, PERSON_WORLD_ID_IDENTITY);
}

#[test(should_fail_with = "already present")]
unconstrained fn unique_second_action_rejected() {
    // The same person under a later registry root is still the same person.
    let env = TestEnvironment::new();
    act(env, 3, 1, 10, PERSON_WORLD_ID_IDENTITY);
    act(env, 3, 2, 10, PERSON_WORLD_ID_IDENTITY);
}

#[test]
unconstrained fn unique_other_person_accepted() {
    let env = TestEnvironment::new();
    act(env, 3, 1, 10, PERSON_WORLD_ID_IDENTITY);
    act(env, 4, 1, 10, PERSON_WORLD_ID_IDENTITY);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn unique_stale_rejected() {
    let env = TestEnvironment::new();
    act(env, 3, 1, 3601, PERSON_WORLD_ID_IDENTITY);
}

#[test(should_fail_with = "Wrong person kind")]
unconstrained fn unique_wrong_person_kind_rejected() {
    let env = TestEnvironment::new();
    act(env, 3, 1, 10, PERSON_NATIONAL_ID);
}

#[test]
unconstrained fn unique_holder_choice_accepted() {
    let env = TestEnvironment::new();
    act_choice(env, 1, SET_BY_HOLDER);
}

#[test(should_fail_with = "A free choice needs holder-chosen evidence")]
unconstrained fn unique_prover_choice_rejected() {
    let env = TestEnvironment::new();
    act_choice(env, 1, SET_BY_PROVER);
}

// Inclusion expiry.

#[test]
unconstrained fn unique_expiry_is_the_freshness_deadline() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = act_opts(env, Option::none(), terms(), 3, 10, false, SET_BY_HOLDER);
    assert_eq(expiry, now - 10 + 3600);
}

#[test]
unconstrained fn unique_at_the_exact_deadline_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = act_opts(env, Option::none(), terms(), 3, 3600, false, SET_BY_HOLDER);
    assert_eq(expiry, now);
}

// Unbound and undated evidence.

#[test(should_fail_with = "Unbound evidence not accepted")]
unconstrained fn unique_unbound_refused_by_default() {
    let env = TestEnvironment::new();
    let _ = act_opts(env, Option::none(), terms(), 3, 10, false, SET_BY_NONE);
}

#[test]
unconstrained fn unique_unbound_accepted_when_allowed() {
    let env = TestEnvironment::new();
    let mut open = terms();
    open.allow_unbound = true;
    let _ = act_opts(env, Option::none(), open, 3, 10, false, SET_BY_NONE);
}

#[test(should_fail_with = "Undated evidence not accepted")]
unconstrained fn unique_undated_refused_by_default() {
    let env = TestEnvironment::new();
    let _ = act_opts(env, Option::none(), terms(), 3, 0, true, SET_BY_HOLDER);
}

#[test]
unconstrained fn unique_undated_accepted_when_allowed() {
    // No freshness deadline applies to undated evidence.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut open = terms();
    open.allow_undated = true;
    let expiry = act_opts(env, Option::none(), open, 3, 0, true, SET_BY_HOLDER);
    assert(expiry > now + 3600);
}

// The public `once` and `once_with_choice` at deployed contracts.

#[test]
unconstrained fn once_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_unique(&mut env, terms());
    let _ = act_opts(env, Option::some(at), terms(), 3, 10, false, SET_BY_HOLDER);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn once_wrong_terms_rejected() {
    // Another scope than the contract commits to.
    let mut env = TestEnvironment::new();
    let at = deploy_unique(&mut env, terms());
    let mut other = terms();
    other.scope = 2;
    let _ = act_opts(env, Option::some(at), other, 3, 10, false, SET_BY_HOLDER);
}

#[test(should_fail_with = "already present")]
unconstrained fn once_second_action_at_contract_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_unique(&mut env, terms());
    let _ = act_opts(env, Option::some(at), terms(), 3, 10, false, SET_BY_HOLDER);
    let _ = act_opts(env, Option::some(at), terms(), 3, 5, false, SET_BY_HOLDER);
}

#[test]
unconstrained fn once_holds_per_deployment_only() {
    // Review B2: nullifiers are siloed per contract. A second deployment, for
    // example after a key rotation or a new pinned root, starts with an empty
    // nullifier set, so the same person acts again with the same scope.
    let mut env = TestEnvironment::new();
    let first = deploy_unique(&mut env, terms());
    let second = deploy_unique(&mut env, terms());
    let _ = act_opts(
        env,
        Option::some(first),
        terms(),
        3,
        10,
        false,
        SET_BY_HOLDER,
    );
    let _ = act_opts(
        env,
        Option::some(second),
        terms(),
        3,
        10,
        false,
        SET_BY_HOLDER,
    );
}

#[test]
unconstrained fn once_with_choice_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_unique(&mut env, terms());
    act_choice_at(env, Option::some(at), terms(), 1, SET_BY_HOLDER);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn once_with_choice_wrong_terms_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_unique(&mut env, terms());
    let mut other = terms();
    other.allow_unbound = true;
    act_choice_at(env, Option::some(at), other, 1, SET_BY_HOLDER);
}
