//! TXE tests of the LINE login link. Each test deploys the keyless
//! `uc_terms_shell` with this instance's terms and runs `link` (the call
//! that the generated entrypoint makes) at its address with the synthetic
//! token from `fixture.nr`. The token's ES256 signature and claims are
//! verified by `line::verify_line_with_iat`. Negative cases mutate the valid
//! fixture. No verification key, proof or network is involved.
use crate::fixture::{
    EXPIRY, ISSUED_AT, later_payload, later_signature, NONCE, NOW, other_key_signature, OTHER_KEY_X, OTHER_KEY_Y, token,
};
use aztec::{
    context::PrivateContext,
    protocol::address::AztecAddress,
    test::helpers::test_environment::{DeployOptions, PrivateContextOptions, TestEnvironment},
};
use uc_adapter_line::{LINE_ISSUER, LineIdToken};
use uc_family_oidc::{bounded_bytes_hash, nonce_of, OidcLink, OidcLogin, OidcProviderInput, subject_id};
use uc_login_link::{DOMAIN_LINK_TERMS, link, link_challenge, link_with_bound_terms, LinkTerms};
use uc_trust::{ALSO_COPY_HOLDER, ANCHOR_NONE, SOURCE_IDENTITY_PROVIDER, terms_commitment, TrustPolicy};

global SCHEME: Field = 22;

/// A short freshness window for the freshness tests (below every lifetime).
global TEST_MAX_AGE: u64 = 20;

/// The instance's deployment terms: the synthetic key and client id, one
/// hour of freshness, no bearer logins.
fn terms() -> LinkTerms {
    LinkTerms {
        accepted: TrustPolicy {
            source: SOURCE_IDENTITY_PROVIDER,
            issuer: token().issuer(),
            anchor_kind: ANCHOR_NONE,
            anchor: 0,
            min_finality: 0,
            refuse_also: ALSO_COPY_HOLDER,
        },
        max_age: 3600,
        allow_bearer: false,
        scope: 1,
        round: 0,
    }
}

/// Deploys the shell with `terms()` and mines a block at `timestamp`, the
/// anchor of the next private context.
unconstrained fn setup(timestamp: u64) -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let at = env
        .deploy_opts(
            DeployOptions::new().with_immutables_hash(terms_commitment(DOMAIN_LINK_TERMS, SCHEME, terms().hash())),
            "@uc_terms_shell/TermsShell",
        )
        .without_initializer();
    env.mine_block_at(timestamp);
    (env, at)
}

/// Runs `f` in a private context at the deployed shell.
unconstrained fn at_shell<Env, T>(
    env: TestEnvironment,
    at: AztecAddress,
    f: unconstrained fn[Env](&mut PrivateContext) -> T,
) -> T {
    env.private_context_opts(PrivateContextOptions::new().at_contract_address(at), f)
}

/// The generated entrypoint body: `uc_login_link::link` with the wrapped token.
unconstrained fn link_token(env: TestEnvironment, at: AztecAddress, input: LineIdToken) -> Field {
    at_shell(
        env,
        at,
        |context| link(context, terms(), OidcLink { input }).identity,
    )
}

/// The rules after term binding, with other terms at the same address (the
/// challenge depends only on `round`, so the fixture still matches it).
unconstrained fn link_with(env: TestEnvironment, at: AztecAddress, other: LinkTerms) -> Field {
    at_shell(
        env,
        at,
        |context| link_with_bound_terms(context, other, OidcLink { input: token() }).identity,
    )
}

/// The identity that a link of the fixture token returns.
fn identity() -> Field {
    subject_id(LINE_ISSUER, bounded_bytes_hash(token().subject))
}

/// The adapter's verification of `input` at `NOW` for the fixture nonce.
unconstrained fn verify_at_now(input: LineIdToken) -> OidcLogin {
    input.verify(nonce_of(NONCE), NOW)
}

/// The second fixture token: the same claims and `exp`, `iat` one second
/// later, signed under the pinned key.
fn later_token() -> LineIdToken {
    let mut input = token();
    input.payload_b64 = later_payload();
    input.signature_b64 = later_signature();
    input
}

/// The fixture token with the other key (and the fixture signature).
fn other_key_token() -> LineIdToken {
    let mut input = token();
    input.public_key_x = OTHER_KEY_X;
    input.public_key_y = OTHER_KEY_Y;
    input
}

#[test]
unconstrained fn valid() {
    let (env, at) = setup(NOW);
    assert_eq(link_token(env, at, token()), identity());
}

#[test]
unconstrained fn inclusion_limited_by_token_expiry() {
    // The token expiry asks for inclusion strictly before exp.
    let (env, at) = setup(NOW);
    let expiry = at_shell(
        env,
        at,
        |context| {
            let _ = link(context, terms(), OidcLink { input: token() });
            (*context).finish().expiration_timestamp
        },
    );
    assert_eq(expiry, EXPIRY - 1);
}

#[test(should_fail_with = "already present")]
unconstrained fn later_login_replay_rejected() {
    // A second login of the same subject is the same identity.
    let (env, at) = setup(NOW);
    let _ = link_token(env, at, token());
    let _ = link_token(env, at, later_token());
}

#[test(should_fail_with = "wrong OIDC audience")]
unconstrained fn wrong_audience_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut audience = input.audience.storage();
    audience[0] += 1;
    input.audience = BoundedVec::from_parts(audience, input.audience.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong OIDC subject")]
unconstrained fn wrong_subject_rejected() {
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut subject = input.subject.storage();
    subject[0] += 1;
    input.subject = BoundedVec::from_parts(subject, input.subject.len());
    let _ = link_token(env, at, input);
}

#[test(should_fail_with = "wrong OIDC nonce")]
unconstrained fn wrong_challenge_rejected() {
    // Another round gives another challenge; the token carries round 0's.
    let (env, at) = setup(NOW);
    let mut other = terms();
    other.round = 1;
    let _ = link_with(env, at, other);
}

#[test]
unconstrained fn reports_the_signed_iat() {
    // The adapter reports the signed iat. The later token has the same
    // exp and an iat one second later, so a value derived from exp would not
    // follow it.
    assert_eq(verify_at_now(token()).issued_at, ISSUED_AT);
    let later = verify_at_now(later_token());
    assert_eq(later.issued_at, ISSUED_AT + 1);
    assert_eq(later.expiry, EXPIRY);
}

#[test(should_fail_with = "Evidence too old")]
unconstrained fn stale_rejected() {
    // A real age (anchor time - signed iat) of max_age + 1 is rejected,
    // while the token is still unexpired.
    let (env, at) = setup(ISSUED_AT + TEST_MAX_AGE + 1);
    let mut other = terms();
    other.max_age = TEST_MAX_AGE;
    let _ = link_with(env, at, other);
}

#[test(should_fail_with = "OIDC token issued in the future")]
unconstrained fn issued_after_now_rejected() {
    // The token's signed iat is after the anchor block.
    let (env, at) = setup(ISSUED_AT - 1);
    let _ = link_token(env, at, token());
}

#[test(should_fail_with = "OIDC token expired")]
unconstrained fn expired_rejected() {
    let (env, at) = setup(EXPIRY);
    let _ = link_token(env, at, token());
}

#[test]
unconstrained fn other_key_verifies_its_own_signature() {
    // The other key with its own signature over the fixture token passes
    // every check: it is a valid P-256 point.
    let mut input = other_key_token();
    input.signature_b64 = other_key_signature();
    assert_eq(verify_at_now(input).subject, verify_at_now(token()).subject);
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn wrong_key_rejected() {
    // The fixture token under another valid key.
    // `other_key_changes_issuer_pin` shows that the key also changes the
    // issuer pin.
    let (env, at) = setup(NOW);
    let _ = link_token(env, at, other_key_token());
}

#[test(should_fail_with = "ES256 signature verification failed")]
unconstrained fn bad_signature_rejected() {
    // The later token's signature (valid r and s under the pinned key, over
    // another payload) on the fixture token.
    let (env, at) = setup(NOW);
    let mut input = token();
    input.signature_b64 = later_signature();
    let _ = link_token(env, at, input);
}

#[test]
unconstrained fn high_s_signature_links_the_same_identity() {
    // ES256 accepts both s and n - s: the other form of the fixture
    // signature verifies too. The link nullifier is per subject, so it
    // still links only once (high_s_replay_rejected).
    let mut input = token();
    input.signature_b64 = flipped_s(input.signature_b64);
    assert_eq(verify_at_now(input).subject, verify_at_now(token()).subject);
}

#[test(should_fail_with = "already present")]
unconstrained fn high_s_replay_rejected() {
    // The other signature form of a linked token cannot link again.
    let (env, at) = setup(NOW);
    let _ = link_token(env, at, token());
    let mut input = token();
    input.signature_b64 = flipped_s(input.signature_b64);
    let _ = link_token(env, at, input);
}

#[test]
unconstrained fn other_key_changes_issuer_pin() {
    // The terms pin the key: another key gives another trust issuer.
    assert(other_key_token().issuer() != token().issuer());
}

#[test(should_fail_with = "LINE channel ID must be decimal")]
unconstrained fn non_decimal_channel_rejected() {
    // A web-login client id is not a channel id; the verifier requires a
    // decimal channel id before the signature check.
    let (env, at) = setup(NOW);
    let mut input = token();
    let mut audience = input.audience.storage();
    audience[0] = 0x61;
    input.audience = BoundedVec::from_parts(audience, input.audience.len());
    let _ = link_token(env, at, input);
}

/// The P-256 group order n, big-endian.
global P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa,
    0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// The base64url alphabet value of an ASCII byte.
fn b64_value(c: u8) -> u8 {
    if (c >= 65) & (c <= 90) {
        c - 65
    } else if (c >= 97) & (c <= 122) {
        c - 71
    } else if (c >= 48) & (c <= 57) {
        c + 4
    } else if c == 45 {
        62
    } else {
        63
    }
}

/// The ASCII byte of a base64url alphabet value.
fn b64_char(v: u8) -> u8 {
    if v < 26 {
        v + 65
    } else if v < 52 {
        v + 71
    } else if v < 62 {
        v - 4
    } else if v == 62 {
        45
    } else {
        95
    }
}

/// The same raw r || s signature (86 base64url characters, 64 bytes) with
/// s replaced by n - s.
unconstrained fn flipped_s(signature: BoundedVec<u8, 86>) -> BoundedVec<u8, 86> {
    let mut bits = [false; 516];
    for i in 0..86 {
        let v = b64_value(signature.get(i));
        for j in 0..6 {
            bits[i * 6 + j] = ((v >> (5 - j as u8)) & 1) == 1;
        }
    }
    let mut raw = [0 as u8; 64];
    for i in 0..64 {
        let mut byte = 0;
        for j in 0..8 {
            byte = byte * 2 + (if bits[i * 8 + j] { 1 } else { 0 });
        }
        raw[i] = byte;
    }
    let mut borrow: u16 = 0;
    for k in 0..32 {
        let i = 31 - k;
        let diff = (P256_ORDER[i] as u16) + 256 - (raw[32 + i] as u16) - borrow;
        raw[32 + i] = (diff % 256) as u8;
        borrow = if diff < 256 { 1 } else { 0 };
    }
    let mut out = [false; 516];
    for i in 0..64 {
        for j in 0..8 {
            out[i * 8 + j] = ((raw[i] >> (7 - j as u8)) & 1) == 1;
        }
    }
    let mut encoded = [0 as u8; 86];
    for i in 0..86 {
        let mut v = 0;
        for j in 0..6 {
            v = v * 2 + (if out[i * 6 + j] { 1 } else { 0 });
        }
        encoded[i] = b64_char(v);
    }
    BoundedVec::from_array(encoded)
}

/// Extended tests: positive variants, fixture diagnostics and extra
/// rejection cases of checks that the tests above already cover.
mod release {
    use super::{
        at_shell, identity, ISSUED_AT, link_challenge, link_token, link_with, NONCE, NOW, setup, terms, TEST_MAX_AGE,
        token,
    };

    #[test]
    unconstrained fn fixture_nonce_is_the_challenge() {
        let (env, at) = setup(NOW);
        let challenge = at_shell(
            env,
            at,
            |context| link_challenge(
                context.chain_id(),
                context.version(),
                context.this_address(),
                uc_trust::msg_sender(*context),
                0,
            ),
        );
        // On failure, regenerate the fixture from aztec/use-cases with
        // node scripts/fixtures/generators/oidc.mjs --instance login-link/line --nonce <challenge>
        assert(challenge == NONCE, f"Fixture nonce is not the challenge {challenge}; regenerate the fixture");
    }

    #[test(should_fail_with = "already present")]
    unconstrained fn padded_subject_replay_rejected() {
        // Bytes after the subject's length do not make a second identity.
        let (env, at) = setup(NOW);
        let _ = link_token(env, at, token());
        let mut padded = token();
        let len = padded.subject.len();
        let mut storage = padded.subject.storage();
        storage[len] = 0x41;
        padded.subject = BoundedVec::from_parts(storage, len);
        let _ = link_token(env, at, padded);
    }

    #[test]
    unconstrained fn fresh_at_max_age_accepted() {
        // At a real age of exactly max_age the login is still fresh.
        // With stale_rejected this pins the reported iat to the fixture's
        // signed iat.
        let (env, at) = setup(ISSUED_AT + TEST_MAX_AGE);
        let mut other = terms();
        other.max_age = TEST_MAX_AGE;
        assert_eq(link_with(env, at, other), identity());
    }
}
