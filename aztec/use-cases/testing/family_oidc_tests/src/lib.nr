//! TXE tests of the OIDC family wrappers (`uc_family_oidc`) with a dummy
//! provider. `DummyToken::verify` makes the checks that a provider library
//! makes (signature, issuer, audience, exact nonce, expiry), with a Poseidon2
//! tag in place of the IdP signature. The tests show that each wrapper puts
//! the core's bound value in the nonce, labels the claim as an OIDC login,
//! and that the cores then apply their rules. The real RS256 path runs in
//! the Google login-link instance (`login-link/google/src/test.nr`).
//!
//! TXE executes the private functions and rejects duplicate nullifiers. It
//! does not prove and does not apply the rollup's expiry check, so expiry
//! tests read the requested expiry.
use aztec::{
    authwit::entrypoint::app::AppPayload,
    context::PrivateContext,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_account::{AccountAuthorisation, action_hash, entrypoint, entrypoint_with_bound_policy};
use uc_attribute_gate::{
    DOMAIN_GATE_BINDING, gate_with_bound_terms, gate_with_choice_with_bound_terms, GateTerms, KIND_ASSURANCE_LEVEL,
    PREDICATE_GE,
};
use uc_family_oidc::{
    issuer_pin, nonce_of, OidcAccount, OidcAttribute, OidcBearerLink, OidcLink, OidcLogin, OidcProviderInput,
    OidcUniqueness, SignedIssueTime, subject_id,
};
use uc_login_link::{link_challenge, link_with_bound_terms, LinkTerms};
use uc_trust::{
    ALSO_CLIENT_OPERATOR, ALSO_COPY_HOLDER, ALSO_IDP, ANCHOR_NONE, caller_binding, caller_choice_binding, SET_BY_CLIENT,
    SET_BY_NONE, SOURCE_IDENTITY_PROVIDER, TrustPolicy,
};
use uc_uniqueness::{DOMAIN_UNIQUE_BINDING, once_with_bound_terms, PERSON_PAIRWISE_SUBJECT, UniqueTerms};

global SCHEME: u32 = 9300;
global ISSUER_NAME: Field = 0x155;
global KEY: Field = 0xbee;
global AUDIENCE: Field = 0xa0d;
global SUBJECT: Field = 0x5b;

/// A dummy ID token with the key and audience that the input pins.
pub struct DummyToken {
    pub key: Field,
    pub issuer_name: Field,
    pub audience: Field,
    pub expected_audience: Field,
    pub subject: Field,
    /// The value whose hex the token carries as its nonce; 0 for a token
    /// without a nonce claim.
    pub nonce: Field,
    pub issued_at: u64,
    pub expiry: u64,
    pub attribute_kind: u32,
    pub attribute: Field,
    pub tag: Field,
}

impl DummyToken {
    fn new(nonce: Field, issued_at: u64, expiry: u64) -> Self {
        DummyToken {
            key: KEY,
            issuer_name: ISSUER_NAME,
            audience: AUDIENCE,
            expected_audience: AUDIENCE,
            subject: SUBJECT,
            nonce,
            issued_at,
            expiry,
            attribute_kind: KIND_ASSURANCE_LEVEL,
            attribute: 3,
            tag: 0,
        }
            .sign()
    }

    fn sign(self) -> Self {
        let mut token = self;
        token.tag = token.signed();
        token
    }

    fn signed(self) -> Field {
        poseidon2_hash([
            self.key,
            self.issuer_name,
            self.audience,
            self.subject,
            self.nonce,
            self.issued_at as Field,
            self.expiry as Field,
            self.attribute_kind as Field,
            self.attribute,
        ])
    }
}

/// The dummy token signs `issued_at` (`signed()`), so its issue time is signed.
impl SignedIssueTime for DummyToken {}

impl OidcProviderInput for DummyToken {
    let SCHEME: u32 = 9300;

    fn policy_hash(self) -> Field {
        poseidon2_hash([self.key, self.expected_audience, self.subject])
    }

    fn verify(self, nonce: BoundedVec<u8, 64>, now: u64) -> OidcLogin {
        assert(self.tag == self.signed(), "Bad token signature");
        assert(self.issuer_name == ISSUER_NAME, "wrong OIDC issuer");
        assert(self.audience == self.expected_audience, "wrong OIDC audience");
        let carried: BoundedVec<u8, 64> = if self.nonce == 0 {
            BoundedVec::new()
        } else {
            nonce_of(self.nonce)
        };
        assert(carried == nonce, "wrong OIDC nonce");
        assert(self.expiry > now, "OIDC token expired");
        OidcLogin {
            issuer: issuer_pin(
                poseidon2_hash([self.key]),
                ISSUER_NAME,
                self.expected_audience,
            ),
            subject: subject_id(ISSUER_NAME, self.subject),
            expiry: self.expiry,
            issued_at: self.issued_at,
            attribute_kind: self.attribute_kind,
            attribute: self.attribute,
        }
    }
}

fn pin() -> Field {
    issuer_pin(poseidon2_hash([KEY]), ISSUER_NAME, AUDIENCE)
}

fn accepted(refuse_also: u8) -> TrustPolicy {
    TrustPolicy {
        source: SOURCE_IDENTITY_PROVIDER,
        issuer: pin(),
        anchor_kind: ANCHOR_NONE,
        anchor: 0,
        min_finality: 0,
        refuse_also,
    }
}

unconstrained fn in_context<Env, T>(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    let mut opts = PrivateContextOptions::new();
    if at.is_some() {
        opts = opts.at_contract_address(at.unwrap());
    }
    env.private_context_opts(opts, f)
}

unconstrained fn requested_expiry(context: &mut PrivateContext) -> u64 {
    (*context).finish().expiration_timestamp
}

// Account authorisation (OidcAccount).

fn payload(tx_nonce: Field) -> AppPayload {
    let mut payload: AppPayload = std::mem::zeroed();
    payload.tx_nonce = tx_nonce;
    payload
}

/// Signs a token over the action hash of `signed` and submits `submitted`.
/// Returns the requested inclusion expiry.
unconstrained fn submit(
    env: TestEnvironment,
    at: Option<AztecAddress>,
    token: DummyToken,
    signed: AppPayload,
    submitted: AppPayload,
) -> u64 {
    in_context(
        env,
        at,
        |context| {
            let mut token = token;
            token.nonce = action_hash(context, SCHEME as Field, signed);
            let auth = OidcAccount { input: token.sign() };
            if at.is_some() {
                entrypoint(context, submitted, auth);
            } else {
                entrypoint_with_bound_policy(context, submitted, auth);
            }
            requested_expiry(context)
        },
    )
}

unconstrained fn deploy_account(env: &mut TestEnvironment, token: DummyToken) -> AztecAddress {
    let auth = OidcAccount { input: token };
    env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(poseidon2_hash([SCHEME as Field, auth.policy_hash()])),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer()
}

#[test]
unconstrained fn account_valid_accepted_with_token_expiry() {
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let token = DummyToken::new(0, now - 30, now + 3600);
    let at = deploy_account(&mut env, token);
    let expiry = submit(env, Option::some(at), token, payload(1), payload(1));
    assert_eq(expiry, now + 3600 - 1);
}

#[test]
unconstrained fn account_grant_is_an_oidc_login_bound_by_the_client() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    in_context(
        env,
        Option::none(),
        |context| {
            let token = DummyToken::new(0x77, now - 30, now + 3600);
            let grant = OidcAccount { input: token }.authorise(context, 0x77);
            assert_eq(grant.trust.source, SOURCE_IDENTITY_PROVIDER);
            assert_eq(grant.trust.issuer, pin());
            assert_eq(grant.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR);
            assert_eq(grant.binding.value, 0x77);
            assert_eq(grant.binding.set_by, SET_BY_CLIENT);
            assert_eq(grant.expiration_timestamp, Option::some(now + 3600 - 1));
            assert(grant.session_nullifier.is_none());
        },
    );
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn account_wrong_action_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = submit(
        env,
        Option::none(),
        DummyToken::new(0, now - 30, now + 3600),
        payload(1),
        payload(2),
    );
}

#[test(should_fail_with = "Wrong account policy")]
unconstrained fn account_wrong_policy_rejected() {
    let mut env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let token = DummyToken::new(0, now - 30, now + 3600);
    let at = deploy_account(&mut env, token);
    let mut other = token;
    other.key = KEY + 1;
    let _ = submit(env, Option::some(at), other, payload(1), payload(1));
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn account_expired_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = submit(
        env,
        Option::none(),
        DummyToken::new(0, now - 30, now),
        payload(1),
        payload(1),
    );
}

#[test(should_fail_with = "already present")]
unconstrained fn account_replay_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let token = DummyToken::new(0, now - 30, now + 3600);
    let _ = submit(env, Option::none(), token, payload(1), payload(1));
    let _ = submit(env, Option::none(), token, payload(1), payload(1));
}

// Login link (OidcLink, OidcBearerLink).

fn link_terms(allow_bearer: bool) -> LinkTerms {
    LinkTerms {
        accepted: accepted(if allow_bearer { 0 } else { ALSO_COPY_HOLDER }),
        max_age: 3600,
        allow_bearer,
        scope: 1,
        round: 0,
    }
}

/// Links with a token over this caller's challenge, or over `nonce` when it
/// is nonzero. Returns (identity, requested expiry).
unconstrained fn link(env: TestEnvironment, terms: LinkTerms, token: DummyToken, nonce: Field) -> (Field, u64) {
    in_context(
        env,
        Option::none(),
        |context| {
            let challenge = link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                terms.round,
            );
            let mut token = token;
            token.nonce = if nonce == 0 { challenge } else { nonce };
            let claim = link_with_bound_terms(context, terms, OidcLink { input: token.sign() });
            assert_eq(claim.binding.set_by, SET_BY_CLIENT);
            assert(!claim.bearer);
            (claim.identity, requested_expiry(context))
        },
    )
}

#[test]
unconstrained fn link_valid_accepted() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let (identity, expiry) = link(
        env,
        link_terms(false),
        DummyToken::new(0, now - 30, now + 600),
        0,
    );
    assert_eq(identity, subject_id(ISSUER_NAME, SUBJECT));
    // The token expiry (exclusive) is earlier than the freshness deadline.
    assert_eq(expiry, now + 600 - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn link_replay_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let token = DummyToken::new(0, now - 30, now + 3600);
    let _ = link(env, link_terms(false), token, 0);
    let _ = link(env, link_terms(false), token, 0);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn link_wrong_issuer_rejected() {
    // A token from another key verifies, but the terms pin this key.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut token = DummyToken::new(0, now - 30, now + 3600);
    token.key = KEY + 1;
    let _ = link(env, link_terms(false), token, 0);
}

#[test(should_fail_with = "Untrusted issuer")]
unconstrained fn link_other_client_rejected() {
    // A token for another client id, with an input that pins that client:
    // it verifies, but the terms pin this client.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut token = DummyToken::new(0, now - 30, now + 3600);
    token.audience = AUDIENCE + 1;
    token.expected_audience = AUDIENCE + 1;
    let _ = link(env, link_terms(false), token, 0);
}

#[test(should_fail_with = "wrong OIDC audience")]
unconstrained fn link_wrong_audience_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut token = DummyToken::new(0, now - 30, now + 3600);
    token.audience = AUDIENCE + 1;
    let _ = link(env, link_terms(false), token, 0);
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn link_wrong_nonce_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = link(
        env,
        link_terms(false),
        DummyToken::new(0, now - 30, now + 3600),
        0xbad,
    );
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn link_expired_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = link(env, link_terms(false), DummyToken::new(0, now - 30, now), 0);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn link_stale_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = link(
        env,
        link_terms(false),
        DummyToken::new(0, now - 3601, now + 3600),
        0,
    );
}

/// Links with a token without a nonce claim through `OidcBearerLink`.
unconstrained fn bearer_link(env: TestEnvironment, terms: LinkTerms, age: u64) -> u64 {
    let now = env.last_block_timestamp();
    in_context(
        env,
        Option::none(),
        |context| {
            let token = DummyToken::new(0, now - age, now + 86400);
            let claim = link_with_bound_terms(context, terms, OidcBearerLink { input: token });
            assert(claim.bearer);
            assert_eq(claim.binding.set_by, SET_BY_NONE);
            // The relying party that receives the token holds a copy too, so the label
            // names the client operator as well.
            assert_eq(claim.trust.also_authorised, ALSO_IDP | ALSO_CLIENT_OPERATOR | ALSO_COPY_HOLDER);
            requested_expiry(context)
        },
    )
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn bearer_link_refused_by_default() {
    // The default terms refuse copy-holder evidence.
    let env = TestEnvironment::new();
    let _ = bearer_link(env, link_terms(false), 30);
}

#[test(should_fail_with = "Bearer login not accepted")]
unconstrained fn bearer_link_refused_without_allow_bearer() {
    let env = TestEnvironment::new();
    let mut terms = link_terms(false);
    terms.accepted.refuse_also = 0;
    let _ = bearer_link(env, terms, 30);
}

#[test(should_fail_with = "Refused co-authority")]
unconstrained fn bearer_link_refused_when_client_operator_refused() {
    // Terms that allow bearer logins but refuse the client operator refuse
    // a bearer token: the client operator receives every token.
    let env = TestEnvironment::new();
    let mut terms = link_terms(true);
    terms.accepted.refuse_also = ALSO_CLIENT_OPERATOR;
    let _ = bearer_link(env, terms, 30);
}

#[test]
unconstrained fn bearer_link_accepted_when_allowed_with_ceiling() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut terms = link_terms(true);
    terms.max_age = 86400;
    // MAX_BEARER_AGE (4 hours) caps the terms' one day.
    assert_eq(bearer_link(env, terms, 30), now - 30 + 14400);
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn link_token_without_nonce_rejected() {
    // A provider without a nonce claim cannot pass as a bound login.
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    in_context(
        env,
        Option::none(),
        |context| {
            let token = DummyToken::new(0, now - 30, now + 3600);
            let _ = link_with_bound_terms(context, link_terms(false), OidcLink { input: token });
        },
    );
}

// Attribute gating (OidcAttribute).

fn gate_terms() -> GateTerms {
    GateTerms {
        accepted: accepted(ALSO_COPY_HOLDER),
        kind: KIND_ASSURANCE_LEVEL,
        predicate: PREDICATE_GE,
        threshold: 2,
        max_age: 3600,
        allow_undated: false,
        allow_unbound: false,
        scope: 1,
    }
}

/// Gates with a token over this caller's binding. Returns the requested expiry.
unconstrained fn gate(env: TestEnvironment, token: DummyToken, terms: GateTerms) -> u64 {
    in_context(
        env,
        Option::none(),
        |context| {
            let mut token = token;
            token.nonce = caller_binding(
                DOMAIN_GATE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
            );
            let claim = gate_with_bound_terms(context, terms, OidcAttribute { input: token.sign() });
            assert_eq(claim.subject, subject_id(ISSUER_NAME, SUBJECT));
            assert_eq(claim.value, 3);
            requested_expiry(context)
        },
    )
}

#[test]
unconstrained fn gate_valid_accepted_until_token_expiry() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let expiry = gate(env, DummyToken::new(0, now - 30, now + 600), gate_terms());
    assert_eq(expiry, now + 600 - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn gate_second_use_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = gate(env, DummyToken::new(0, now - 30, now + 600), gate_terms());
    let _ = gate(env, DummyToken::new(0, now - 10, now + 900), gate_terms());
}

#[test(should_fail_with = "Attribute predicate false")]
unconstrained fn gate_predicate_false_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut terms = gate_terms();
    terms.threshold = 4;
    let _ = gate(env, DummyToken::new(0, now - 30, now + 600), terms);
}

#[test(should_fail_with = "Provider discloses no attribute")]
unconstrained fn gate_provider_without_attribute_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut token = DummyToken::new(0, now - 30, now + 600);
    token.attribute_kind = 0;
    let _ = gate(env, token, gate_terms());
}

#[test]
unconstrained fn gate_with_choice_accepted_for_client_bound_token() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    in_context(
        env,
        Option::none(),
        |context| {
            let binding = caller_choice_binding(
                DOMAIN_GATE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                7,
            );
            let token = DummyToken::new(binding, now - 30, now + 600);
            let _ = gate_with_choice_with_bound_terms(context, gate_terms(), OidcAttribute { input: token }, 7);
        },
    );
}

// Uniqueness (OidcUniqueness).

fn unique_terms() -> UniqueTerms {
    UniqueTerms {
        accepted: accepted(ALSO_COPY_HOLDER),
        person_kind: PERSON_PAIRWISE_SUBJECT,
        max_age: 3600,
        allow_undated: false,
        allow_unbound: false,
        scope: 1,
    }
}

unconstrained fn once(env: TestEnvironment, token: DummyToken, terms: UniqueTerms) -> u64 {
    in_context(
        env,
        Option::none(),
        |context| {
            let mut token = token;
            token.nonce = caller_binding(
                DOMAIN_UNIQUE_BINDING,
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
            );
            let claim = once_with_bound_terms(context, terms, OidcUniqueness { input: token.sign() });
            assert_eq(claim.person, subject_id(ISSUER_NAME, SUBJECT));
            requested_expiry(context)
        },
    )
}

#[test]
unconstrained fn once_valid_accepted_until_token_expiry() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    assert_eq(once(env, DummyToken::new(0, now - 30, now + 600), unique_terms()), now + 600 - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn once_second_use_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = once(env, DummyToken::new(0, now - 30, now + 600), unique_terms());
    let _ = once(env, DummyToken::new(0, now - 10, now + 900), unique_terms());
}

#[test(should_fail_with = "Wrong person kind")]
unconstrained fn once_wrong_person_kind_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let mut terms = unique_terms();
    terms.person_kind = PERSON_PAIRWISE_SUBJECT - 1;
    let _ = once(env, DummyToken::new(0, now - 30, now + 600), terms);
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn once_expired_rejected() {
    let env = TestEnvironment::new();
    let now = env.last_block_timestamp();
    let _ = once(env, DummyToken::new(0, now - 30, now), unique_terms());
}
