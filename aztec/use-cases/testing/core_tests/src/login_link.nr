use crate::{deploy_with_immutables, in_context, requested_expiry};
use aztec::{
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::TestEnvironment,
};
use uc_login_link::{
    DOMAIN_LINK_TERMS, link as link_core, link_challenge, link_with_bound_terms, LinkClaim, LinkTerms, LoginLink,
};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_COPY_HOLDER, ALSO_IDP, ANCHOR_NONE, Binding, SET_BY_CLIENT, SET_BY_NONE,
    SOURCE_IDENTITY_PROVIDER, terms_commitment, Trust, TrustPolicy,
};

global SCHEME: u32 = 9002;

global IDP_KEY: Field = 0x1d9;

/// A dummy OIDC login. `tag` stands in for the IdP's token signature over
/// (subject, nonce, iat, exp).
pub struct DummyLogin {
    pub idp_key: Field,
    pub subject: Field,
    pub nonce: Field,
    pub issued_at: u64,
    pub expires_at: u64,
    pub bearer: bool,
    pub tag: Field,
}

impl DummyLogin {
    fn new(subject: Field, nonce: Field, issued_at: u64, expires_at: u64, bearer: bool) -> Self {
        let mut login = DummyLogin { idp_key: IDP_KEY, subject, nonce, issued_at, expires_at, bearer, tag: 0 };
        login.tag = login.signed();
        login
    }

    fn signed(self) -> Field {
        poseidon2_hash([
            self.idp_key,
            self.subject,
            self.nonce,
            self.issued_at as Field,
            self.expires_at as Field,
            self.bearer as Field,
        ])
    }
}

impl LoginLink for DummyLogin {
    let SCHEME: u32 = 9002;

    fn verify(self, _context: &mut PrivateContext, _challenge: Field) -> LinkClaim {
        assert(self.tag == self.signed(), "Bad token signature");
        let issuer = poseidon2_hash([self.idp_key]);
        LinkClaim {
            trust: Trust {
                source: SOURCE_IDENTITY_PROVIDER,
                issuer,
                anchor_kind: ANCHOR_NONE,
                anchor: 0,
                finality: 0,
                also_authorised: if self.bearer {
                    ALSO_IDP | ALSO_COPY_HOLDER
                } else {
                    ALSO_IDP | ALSO_CLIENT_OPERATOR
                },
            },
            identity: poseidon2_hash([issuer, self.subject]),
            binding: if self.bearer {
                Binding { value: 0, set_by: SET_BY_NONE }
            } else {
                Binding { value: self.nonce, set_by: SET_BY_CLIENT }
            },
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            bearer: self.bearer,
        }
    }
}

fn terms(allow_bearer: bool) -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: poseidon2_hash([IDP_KEY]),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: 0,
        },
        max_age: 86400,
        allow_bearer,
        scope: 1,
        round: 0,
    }
}

/// Links with a login whose nonce is this caller's challenge (or `nonce` when
/// nonzero) and returns the requested inclusion expiry. With `at`, the
/// public `link` runs at that deployed contract; without it,
/// `link_with_bound_terms` runs at the TXE default address.
unconstrained fn link_at(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    terms: LinkTerms,
    subject: Field,
    nonce: Field,
    age: u64,
    expires_in: u64,
    bearer: bool,
) -> u64 {
    let now = env.last_block_timestamp();
    in_context(
        env,
        at,
        |context| {
            let challenge = link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                terms.round,
            );
            let signed_nonce = if nonce == 0 { challenge } else { nonce };
            let expires_at = if expires_in == 0 { 0 } else { now + expires_in };
            let login = DummyLogin::new(subject, signed_nonce, now - age, expires_at, bearer);
            let claim = if at.is_some() {
                link_core(context, terms, login)
            } else {
                link_with_bound_terms(context, terms, login)
            };
            assert_eq(claim.identity, poseidon2_hash([poseidon2_hash([IDP_KEY]), subject]));
            requested_expiry(context)
        },
    )
}

unconstrained fn link(
    env: TestEnvironment,
    terms: LinkTerms,
    subject: Field,
    nonce: Field,
    age: u64,
    expires_in: u64,
    bearer: bool,
) -> u64 {
    link_at(
        env,
        Option::none(),
        terms,
        subject,
        nonce,
        age,
        expires_in,
        bearer,
    )
}

unconstrained fn deploy_link(env: &mut TestEnvironment, terms: LinkTerms) -> AztecAddress {
    deploy_with_immutables(
        env,
        terms_commitment(DOMAIN_LINK_TERMS, SCHEME as Field, terms.hash()),
    )
}

#[test]
unconstrained fn link_valid_accepted() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0, 30, 3600, false);
}

#[test(should_fail_with = "already present")]
unconstrained fn link_replay_rejected() {
    // One link per identity per app, even with a second fresh login.
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0, 30, 3600, false);
    let _ = link(env, terms(false), 5, 0, 10, 3600, false);
}

#[test]
unconstrained fn link_other_identity_accepted() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0, 30, 3600, false);
    let _ = link(env, terms(false), 6, 0, 30, 3600, false);
}

#[test(should_fail_with = "Login bound to another challenge")]
unconstrained fn link_wrong_challenge_rejected() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0xbad, 30, 3600, false);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn link_stale_rejected() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0, 86401, 3600, false);
}

#[test(should_fail_with = "Evidence expired")]
unconstrained fn link_expired_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    env.private_context(|context| {
        let challenge = link_challenge(
            context.chain_id(),
            context.version(),
            context.this_address(),
            uc_trust::msg_sender(*context),
            0,
        );
        let login = DummyLogin::new(5, challenge, now - 30, now, false);
        let _ = link_with_bound_terms(context, terms(false), login);
    });
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn link_wrong_issuer_rejected() {
    let env = TestEnvironment::new();
    let mut other = terms(false);
    other.accepted.issuer = 1;
    let _ = link(env, other, 5, 0, 30, 3600, false);
}

#[test(should_fail_with = "Bearer login not accepted")]
unconstrained fn link_bearer_refused_by_default() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(false), 5, 0, 30, 3600, true);
}

#[test]
unconstrained fn link_bearer_accepted_when_allowed() {
    let env = TestEnvironment::new();
    let _ = link(env, terms(true), 5, 0, 30, 3600, true);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn link_bearer_has_a_freshness_ceiling() {
    // Within the terms' 24 hours, but beyond MAX_BEARER_AGE for a bearer login.
    let env = TestEnvironment::new();
    let _ = link(env, terms(true), 5, 0, 14401, 3600, true);
}

// Inclusion expiry: the earlier of the freshness deadline and
// the last second before the credential's exclusive expiry.

#[test]
unconstrained fn link_expiry_is_the_freshness_deadline() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = link(env, terms(false), 5, 0, 30, 0, false);
    assert_eq(expiry, now - 30 + 86400);
}

#[test]
unconstrained fn link_at_the_exact_freshness_deadline_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = link(env, terms(false), 5, 0, 86400, 0, false);
    assert_eq(expiry, now);
}

#[test]
unconstrained fn link_credential_expiry_limits_inclusion() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = link(env, terms(false), 5, 0, 30, 60, false);
    assert_eq(expiry, now + 59);
}

#[test]
unconstrained fn link_one_second_before_expiry_accepted() {
    // The credential expires one second after the anchor block: it is valid
    // at the anchor block and must be included at that timestamp.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = link(env, terms(false), 5, 0, 30, 1, false);
    assert_eq(expiry, now);
}

#[test]
unconstrained fn link_bearer_expiry_is_the_bearer_ceiling() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = link(env, terms(true), 5, 0, 30, 0, true);
    assert_eq(expiry, now - 30 + 14400);
}

// The public `link` at deployed contracts.

#[test]
unconstrained fn link_at_contract_accepted() {
    let mut env = TestEnvironment::new();
    let at = deploy_link(&mut env, terms(false));
    let _ = link_at(env, Option::some(at), terms(false), 5, 0, 30, 3600, false);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn link_wrong_terms_rejected() {
    // A caller cannot turn on bearer logins that the contract refuses.
    let mut env = TestEnvironment::new();
    let at = deploy_link(&mut env, terms(false));
    let _ = link_at(env, Option::some(at), terms(true), 5, 0, 30, 3600, true);
}
