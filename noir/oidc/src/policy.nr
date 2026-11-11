//! Required root string claims after the selected OIDC JSON profile has been validated.
use crate::{Claims, ClaimsWithIat, parse_claims_profile, parse_claims_profile_with_iat};

pub fn claims_with_required_string<let N: u32, let K: u32>(
    input: BoundedVec<u8, N>,
    profile: u8,
    name: str<K>,
) -> (Claims, BoundedVec<u8, 256>) {
    let claims = parse_claims_profile(input, profile).claims;
    (claims, required_string(input, name))
}

pub fn claims_with_iat_and_required_string<let N: u32, let K: u32>(
    input: BoundedVec<u8, N>,
    profile: u8,
    name: str<K>,
) -> (ClaimsWithIat, BoundedVec<u8, 256>) {
    let claims = parse_claims_profile_with_iat(input, profile);
    (claims, required_string(input, name))
}

// Caller must first validate the complete JSON document and selected identity claims.
fn required_string<let N: u32, let K: u32>(
    input: BoundedVec<u8, N>,
    name: str<K>,
) -> BoundedVec<u8, 256> {
    let mut depth = 0u32;
    let mut quoted = false;
    // The flat profile admits escapes in ignored values, so this rescan
    // skips an escaped byte; it never ends a string.
    let mut escaped = false;
    let mut key_expected = false;
    let mut string_is_key = false;
    let mut start = 0u32;
    let mut selected = false;
    let mut seen = false;
    let mut value_start = 0u32;
    let mut value_len = 0u32;
    for i in 0..N {
        if i < input.len() {
            let b = input.storage()[i];
            if quoted {
                if escaped {
                    escaped = false;
                } else if b == 92 {
                    escaped = true;
                    assert(
                        !((depth == 1) & !string_is_key & selected),
                        "required OIDC claim escape unsupported",
                    );
                } else if b == 34 {
                    quoted = false;
                    if depth == 1 {
                        if string_is_key {
                            let mut same = i - start == K;
                            for j in 0..K {
                                if j < i - start {
                                    same =
                                        same & (input.storage()[start + j] == name.as_bytes()[j]);
                                }
                            }
                            selected = same;
                        } else if selected {
                            assert(!seen, "duplicate required OIDC claim");
                            seen = true;
                            value_start = start;
                            value_len = i - start;
                        }
                    }
                }
            } else if b == 34 {
                quoted = true;
                start = i + 1;
                string_is_key = (depth == 1) & key_expected;
            } else if (b == 123) | (b == 91) {
                if depth == 1 {
                    assert(!selected, "required OIDC claim must be string");
                }
                depth += 1;
                if depth == 1 {
                    key_expected = true;
                }
            } else if (b == 125) | (b == 93) {
                depth -= 1;
            } else if depth == 1 {
                if b == 58 {
                    key_expected = false;
                } else if b == 44 {
                    key_expected = true;
                    selected = false;
                } else if !key_expected & selected & !((b == 32) | (b == 9) | (b == 10) | (b == 13))
                     {
                        assert(false, "required OIDC claim must be string");
                    }
            }
        }
    }
    assert(seen, "missing required OIDC claim");
    // The scanner does not cap an ignored value at 256 bytes.
    assert(value_len <= 256, "required OIDC claim too long");
    let mut value = BoundedVec::<u8, 256>::new();
    for j in 0..256 {
        if j < value_len {
            value.push(input.storage()[value_start + j]);
        }
    }
    value
}

#[test]
fn direct_root_assurance_and_amr() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"amr\":[\"fc\",\"pwd\"],\"acr\":\"eidas2\"}",
    );
    let (_, value) = claims_with_required_string(input, 1, "acr");
    assert(crate::string_matches(value, crate::literal_vec("eidas2")));
}
#[test(should_fail_with = "duplicate required OIDC claim")]
fn duplicate_extra_root_claim_rejects() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"acr\":\"eidas2\",\"acr\":\"eidas3\"}",
    );
    let _ = claims_with_required_string(input, 1, "acr");
}
#[test(should_fail_with = "missing required OIDC claim")]
fn array_string_cannot_be_root_key() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"amr\":[\"acr\",\"eidas3\"]}",
    );
    let _ = claims_with_required_string(input, 1, "acr");
}
#[test(should_fail_with = "required OIDC claim must be string")]
fn scalar_extra_claim_rejects() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"acr\":3}",
    );
    let _ = claims_with_required_string(input, 1, "acr");
}
#[test]
fn root_assurance_with_signed_iat() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":5,\"exp\":10,\"amr\":[\"fc\"],\"acr\":\"eidas2\"}",
    );
    let (claims, value) = claims_with_iat_and_required_string(input, 1, "acr");
    assert(claims.issued_at == 5);
    assert(crate::string_matches(value, crate::literal_vec("eidas2")));
}
#[test(should_fail_with = "missing OIDC iat claim")]
fn missing_iat_rejects() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"acr\":\"eidas2\"}",
    );
    let _ = claims_with_iat_and_required_string(input, 1, "acr");
}
#[test]
fn copy_agrees_with_claims_with_required_string() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":5,\"exp\":10,\"amr\":[\"acr\"],\"acr\":\"eidas3\"}",
    );
    let (a, x) = claims_with_required_string(input, 1, "acr");
    let (b, y) = claims_with_iat_and_required_string(input, 1, "acr");
    assert(crate::string_matches(x, y));
    assert(crate::string_matches(a.subject, b.claims.subject));
    assert(a.expiry == b.claims.expiry);
}

// An escaped quote in an ignored value must not desynchronise
// the rescan. Here a raw quote-and-bracket scan would read the nested x.acr
// as the root claim and skip the real root acr.
#[test]
fn escaped_quote_cannot_promote_a_nested_acr() {
    let input = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":10,\"u1\":\"\\\"}\\\"\",\"x\":{\"acr\":\"eidas3\"},\"u2\":\"\\\"{,{\\\"\",\"acr\":\"eidas1\"}",
    );
    let (_, a) = claims_with_required_string(input, 1, "acr");
    let (_, b) = claims_with_iat_and_required_string(input, 1, "acr");
    assert(crate::string_matches(a, crate::literal_vec("eidas1")));
    assert(crate::string_matches(b, crate::literal_vec("eidas1")));
}
#[test(should_fail_with = "required OIDC claim escape unsupported")]
fn escaped_required_claim_rejected() {
    let _ = claims_with_required_string(
        crate::literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"acr\":\"eid\\/as1\"}",
        ),
        1,
        "acr",
    );
}
#[test(should_fail_with = "required OIDC claim too long")]
fn long_required_claim_rejected() {
    let mut input = BoundedVec::<u8, 512>::new();
    for b in "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":10,\"acr\":\""
        .as_bytes() {
        input.push(b);
    }
    for _ in 0..257 {
        input.push(120);
    }
    input.push(34);
    input.push(125);
    let _ = claims_with_iat_and_required_string(input, 1, "acr");
}
#[test(should_fail_with = "required OIDC claim escape unsupported")]
fn escaped_required_claim_rejected_with_iat() {
    let _ = claims_with_iat_and_required_string(
        crate::literal_vec(
            "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"iat\":1,\"exp\":10,\"acr\":\"eid\\/as1\"}",
        ),
        1,
        "acr",
    );
}
#[test(should_fail_with = "required OIDC claim too long")]
fn long_required_claim_rejected_without_iat() {
    let mut input = BoundedVec::<u8, 512>::new();
    for b in "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":10,\"acr\":\""
        .as_bytes() {
        input.push(b);
    }
    for _ in 0..257 {
        input.push(120);
    }
    input.push(34);
    input.push(125);
    let _ = claims_with_required_string(input, 1, "acr");
}
