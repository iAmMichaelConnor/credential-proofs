// Benchmark entry points: one #[export] function per verified relation, with the
// inputs of its end-to-end known-answer test. `nargo export` compiles each to its
// own program for the gates report. Parameters carry no `pub` (an exported
// function has no public inputs); otherwise each body is the complete relation.

use crate::{JwtInput, literal_vec, TrustedP256Key, TrustedRsaKey};

// Verify an Apple ID token against the expected audience, subject, nonce and time.
#[export]
pub(crate) fn oidc_apple(
    token: JwtInput<128, 1024, 344>,
    trusted_key: TrustedRsaKey,
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 64>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> [u128; 18] {
    // The modulus limbs are the public output, which a verifier compares with its
    // trusted key. The redc limbs stay private: they are a range-checked Barrett
    // hint, several values verify one key, and a public redc would let one proof
    // match many public-input vectors.
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _claims = crate::verify_apple(token, audience, subject, nonce, now, trusted_key);
    trusted_key.modulus_limbs
}

// Verify a Google ID token against the expected audience, subject, nonce and time.
#[export]
pub(crate) fn oidc_google(
    token: JwtInput<128, 1024, 344>,
    trusted_key: TrustedRsaKey,
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 64>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) -> [u128; 18] {
    // The modulus limbs are the public output, which a verifier compares with its
    // trusted key. The redc limbs stay private: they are a range-checked Barrett
    // hint, several values verify one key, and a public redc would let one proof
    // match many public-input vectors.
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(audience);
    canonical_bytes::assert_canonical(subject);
    canonical_bytes::assert_canonical(nonce);
    let _claims = crate::verify_google(token, audience, subject, nonce, now, trusted_key);
    trusted_key.modulus_limbs
}

// Verify an ES256 JWT against fixed issuer, client, user and nonce values.
#[export]
pub(crate) fn oidc_es256_jwt(token: JwtInput<64, 128, 86>, key: TrustedP256Key, now: u64) {
    let _claims = token.verify_es256(
        literal_vec("issuer"),
        literal_vec("client"),
        literal_vec("user"),
        literal_vec("nonce"),
        now,
        key,
    );
}

// Select bounded root JSON members with conditional brokered-field selection.
// Repeated-scan baseline. Variable bounded document, selected root spans,
// presence and brokered conditional selection; no signature/authentication.
#[export]
pub(crate) fn oidc_json_member_batch(
    document: BoundedVec<u8, 512>,
    brokered: bool,
    expected: [crate::JsonSpan; 8],
    present: [bool; 8],
) {
    let root = crate::assert_json_document(document);
    let (a, ap) = crate::json_optional_member(document, root, "iss");
    let (b, bp) = crate::json_optional_member(document, root, "aud");
    let (c, cp) = crate::json_optional_member(document, root, "sub");
    let (d, dp) = crate::json_optional_member(document, root, "nonce");
    let (e, ep) = crate::json_optional_member(document, root, "exp");
    let (f, fp) = crate::json_optional_member(document, root, "iat");
    let (g, gp) = crate::json_optional_member(document, root, "nbf");
    let (h, hp) = if brokered {
        crate::json_optional_member(document, root, "idp")
    } else {
        (crate::JsonSpan { start: 0, end: 0, kind: 0 }, false)
    };
    let actual = [a, b, c, d, e, f, g, h];
    let found = [ap, bp, cp, dp, ep, fp, gp, hp];
    for i in 0..8 {
        assert(actual[i].start == expected[i].start);
        assert(actual[i].end == expected[i].end);
        assert(actual[i].kind == expected[i].kind);
        assert(found[i] == present[i]);
    }
}

// Parse a JSON document and bind its root iat member to the expected integer.
// Variable document and member value; not a signature/authentication relation.
#[export]
pub(crate) fn oidc_json_member_lookup(document: BoundedVec<u8, 256>, expected: u64) {
    let root = crate::assert_json_document(document);
    assert(crate::json_u64(document, crate::json_member(document, root, "iat")) == expected);
}

// Copy a selected JSON string span into a bounded expected value.
// Extraction component only. A production caller first validates JSON and
// derives span from constrained root/member selection; no signature here.
#[export]
pub(crate) fn oidc_json_string_copy(
    document: BoundedVec<u8, 1536>,
    span: crate::JsonSpan,
    expected: BoundedVec<u8, 256>,
) {
    // Public byte strings must be zero-padded (canonical public inputs).
    canonical_bytes::assert_canonical(expected);
    assert(document.len() <= 1536);
    let copied: BoundedVec<u8, 256> = crate::json_string(document, span);
    assert(crate::string_matches(copied, expected));
}
