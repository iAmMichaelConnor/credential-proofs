//! The shared term binding against deployed instances: the contract address
//! commits to `immutables_hash`, and `bind_terms` and `bind_policy` accept
//! only the terms that hash to it.
use crate::{deploy_with_immutables, in_context};
use aztec::{protocol::hash::poseidon2_hash, test::helpers::test_environment::TestEnvironment};
use uc_account::bind_policy;
use uc_trust::{bind_terms, terms_commitment};

global DOMAIN: Field = 0xd0;
global SCHEME: Field = 9100;
global TERMS: Field = 0x7e5;

#[test]
unconstrained fn bind_terms_accepts_committed_terms() {
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, terms_commitment(DOMAIN, SCHEME, TERMS));
    in_context(
        env,
        Option::some(at),
        |context| bind_terms(context, DOMAIN, SCHEME, TERMS),
    );
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn bind_terms_wrong_terms_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, terms_commitment(DOMAIN, SCHEME, TERMS));
    in_context(
        env,
        Option::some(at),
        |context| bind_terms(context, DOMAIN, SCHEME, TERMS + 1),
    );
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn bind_terms_wrong_scheme_rejected() {
    // The same terms committed for another scheme do not bind.
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, terms_commitment(DOMAIN, SCHEME, TERMS));
    in_context(
        env,
        Option::some(at),
        |context| bind_terms(context, DOMAIN, SCHEME + 1, TERMS),
    );
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn bind_terms_wrong_domain_rejected() {
    // The same terms committed for another use case do not bind.
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, terms_commitment(DOMAIN, SCHEME, TERMS));
    in_context(
        env,
        Option::some(at),
        |context| bind_terms(context, DOMAIN + 1, SCHEME, TERMS),
    );
}

#[test]
unconstrained fn bind_policy_accepts_committed_policy() {
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, poseidon2_hash([SCHEME, TERMS]));
    in_context(
        env,
        Option::some(at),
        |context| bind_policy(context, SCHEME, TERMS),
    );
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn bind_policy_wrong_policy_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, poseidon2_hash([SCHEME, TERMS]));
    in_context(
        env,
        Option::some(at),
        |context| bind_policy(context, SCHEME, TERMS + 1),
    );
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn bind_policy_wrong_scheme_rejected() {
    let mut env = TestEnvironment::new();
    let at = deploy_with_immutables(&mut env, poseidon2_hash([SCHEME, TERMS]));
    in_context(
        env,
        Option::some(at),
        |context| bind_policy(context, SCHEME + 1, TERMS),
    );
}
