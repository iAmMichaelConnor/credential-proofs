//! Standard one-string-audience OIDC claims from a validated structured document.
//! This parser does not authenticate JSON; callers verify these exact bytes first.
use crate::{
    assert_json_document, Claims, json_member, json_optional_member, json_string, json_u64,
    JsonSpan, string_matches,
};

fn ws(b: u8) -> bool {
    (b == 32) | (b == 9) | (b == 10) | (b == 13)
}

/// One pass over an array span of a validated document (so its strings are
/// unescaped): every element must be a string. Returns whether one element
/// equals `expected`, and the number of elements.
fn string_array_contains<let N: u32>(
    input: BoundedVec<u8, N>,
    array: JsonSpan,
    expected: BoundedVec<u8, 256>,
) -> (bool, u32) {
    assert((array.start < array.end) & (array.end <= input.len()));
    assert(
        (array.kind == 91)
            & (input.storage()[array.start] == 91)
            & (input.storage()[array.end - 1] == 93),
        "JSON value must be array",
    );
    let mut quoted = false;
    let mut count = 0;
    let mut position = 0;
    let mut same = false;
    let mut found = false;
    for i in 0..N {
        if (i > array.start) & (i + 1 < array.end) {
            let b = input.storage()[i];
            if quoted {
                if b == 34 {
                    quoted = false;
                    found = found | (same & (position == expected.len()));
                } else {
                    if position < 256 {
                        same = same & (b == expected.storage()[position]);
                    }
                    position += 1;
                }
            } else if b == 34 {
                quoted = true;
                count += 1;
                position = 0;
                same = true;
            } else {
                assert(ws(b) | (b == 44), "aud array must contain strings");
            }
        }
    }
    (found, count)
}
pub struct DocumentClaims {
    pub claims: Claims,
    pub issued_at: u64,
    pub root: JsonSpan,
}
pub fn parse_document_claims<let N: u32>(payload: BoundedVec<u8, N>) -> DocumentClaims {
    let root = assert_json_document(payload);
    let issuer = json_string(payload, json_member(payload, root, "iss"));
    let audience = json_string(payload, json_member(payload, root, "aud"));
    let subject = json_string(payload, json_member(payload, root, "sub"));
    let nonce = json_string(payload, json_member(payload, root, "nonce"));
    let expiry = json_u64(payload, json_member(payload, root, "exp"));
    let issued_at = json_u64(payload, json_member(payload, root, "iat"));
    let (nbf, has_not_before) = json_optional_member(payload, root, "nbf");
    let not_before = if has_not_before {
        json_u64(payload, nbf)
    } else {
        0
    };
    let (azp, has_azp) = json_optional_member(payload, root, "azp");
    let authorized_party = if has_azp {
        json_string(payload, azp)
    } else {
        BoundedVec::new()
    };
    if has_azp {
        assert(string_matches(authorized_party, audience), "azp must match aud");
    }
    DocumentClaims {
        claims: Claims {
            issuer,
            audience,
            subject,
            nonce,
            expiry,
            authorized_party,
            not_before,
            has_not_before,
        },
        issued_at,
        root,
    }
}

/// As `parse_document_claims`, for a provider whose ID token may carry `aud`
/// as an array (OIDC Core 1.0 section 2). `aud` is
/// either one string or a non-empty array of strings that contains
/// `expected_audience`. With more than one audience, `azp` is required (OIDC
/// Core 1.0 section 3.1.3.7). A present `azp` must equal the audience, so with
/// an array it must equal `expected_audience`. The returned `claims.audience`
/// is the string `aud`, or `expected_audience` when the array contains it.
/// Every other rule is that of `parse_document_claims`.
pub fn parse_document_claims_for_audience<let N: u32>(
    payload: BoundedVec<u8, N>,
    expected_audience: BoundedVec<u8, 256>,
) -> DocumentClaims {
    let root = assert_json_document(payload);
    let issuer = json_string(payload, json_member(payload, root, "iss"));
    let aud = json_member(payload, root, "aud");
    let mut audience = BoundedVec::new();
    let mut audiences = 1;
    if aud.kind == 91 {
        let (found, count) = string_array_contains(payload, aud, expected_audience);
        assert(found, "aud must contain the expected audience");
        audiences = count;
        audience = expected_audience;
    } else {
        audience = json_string(payload, aud);
    }
    let subject = json_string(payload, json_member(payload, root, "sub"));
    let nonce = json_string(payload, json_member(payload, root, "nonce"));
    let expiry = json_u64(payload, json_member(payload, root, "exp"));
    let issued_at = json_u64(payload, json_member(payload, root, "iat"));
    let (nbf, has_not_before) = json_optional_member(payload, root, "nbf");
    let not_before = if has_not_before {
        json_u64(payload, nbf)
    } else {
        0
    };
    let (azp, has_azp) = json_optional_member(payload, root, "azp");
    let authorized_party = if has_azp {
        json_string(payload, azp)
    } else {
        BoundedVec::new()
    };
    assert(has_azp | (audiences == 1), "azp is required with several audiences");
    if has_azp {
        assert(string_matches(authorized_party, audience), "azp must match aud");
    }
    DocumentClaims {
        claims: Claims {
            issuer,
            audience,
            subject,
            nonce,
            expiry,
            authorized_party,
            not_before,
            has_not_before,
        },
        issued_at,
        root,
    }
}

#[test]
fn document_standard_claims_nested_and_optional() {
    let p = crate::literal_vec(
        "{\"iss\":\"issuer\",\"aud\":\"client\",\"sub\":\"subject\",\"nonce\":\"action\",\"exp\":200,\"iat\":90,\"nbf\":80,\"azp\":\"client\",\"other\":{\"iss\":\"evil\"}}",
    );
    let parsed = parse_document_claims(p);
    assert(parsed.issued_at == 90);
    assert(parsed.claims.has_not_before);
    crate::assert_claims_policy(
        parsed.claims,
        crate::literal_vec("issuer"),
        crate::literal_vec("client"),
        crate::literal_vec("subject"),
        crate::literal_vec("action"),
        100,
    );
}
#[test(should_fail_with = "azp must match aud")]
fn document_standard_claims_wrong_azp() {
    let p = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":200,\"iat\":90,\"azp\":\"other\"}",
    );
    let _parsed = parse_document_claims(p);
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn document_standard_claims_duplicate_iat() {
    let p = crate::literal_vec(
        "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":200,\"iat\":null,\"iat\":90}",
    );
    let _parsed = parse_document_claims(p);
}

// Accept aud as a string or an array.
fn audience_claims<let N: u32>(aud_and_azp: str<N>) -> BoundedVec<u8, 256> {
    let head = "{\"iss\":\"i\",\"sub\":\"s\",\"nonce\":\"n\",\"exp\":200,\"iat\":90,";
    let mut out = BoundedVec::<u8, 256>::new();
    for b in head.as_bytes() {
        out.push(b);
    }
    for i in 0..N {
        out.push(aud_and_azp.as_bytes()[i]);
    }
    out.push(125);
    out
}
#[test]
fn audience_string_and_arrays() {
    let rp = crate::literal_vec("https://rp.example");
    for parsed in [
        parse_document_claims_for_audience(audience_claims("\"aud\":\"https://rp.example\""), rp),
        parse_document_claims_for_audience(audience_claims("\"aud\":[\"https://rp.example\"]"), rp),
        parse_document_claims_for_audience(
            audience_claims(
                "\"aud\":[ \"https://other.example\" , \"https://rp.example\" ],\"azp\":\"https://rp.example\"",
            ),
            rp,
        ),
    ] {
        assert(string_matches(parsed.claims.audience, rp));
        assert(parsed.issued_at == 90);
    }
}
#[test(should_fail_with = "azp is required with several audiences")]
fn audience_array_of_two_requires_azp() {
    let _ = parse_document_claims_for_audience(
        audience_claims("\"aud\":[\"https://rp.example\",\"https://other.example\"]"),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "azp must match aud")]
fn audience_array_with_another_azp() {
    let _ = parse_document_claims_for_audience(
        audience_claims(
            "\"aud\":[\"https://rp.example\",\"https://other.example\"],\"azp\":\"https://other.example\"",
        ),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "aud must contain the expected audience")]
fn audience_array_without_the_audience() {
    let _ = parse_document_claims_for_audience(
        audience_claims(
            "\"aud\":[\"https://rp.example/\",\"https://rp.exampl\"],\"azp\":\"x\"",
        ),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "aud must contain the expected audience")]
fn audience_empty_array() {
    let _ = parse_document_claims_for_audience(
        audience_claims("\"aud\":[]"),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "aud array must contain strings")]
fn audience_array_of_arrays() {
    let _ = parse_document_claims_for_audience(
        audience_claims("\"aud\":[[\"https://rp.example\"]]"),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "JSON member must be string")]
fn audience_number() {
    let _ = parse_document_claims_for_audience(
        audience_claims("\"aud\":7"),
        crate::literal_vec("https://rp.example"),
    );
}
#[test(should_fail_with = "JSON member must be string")]
fn audience_array_still_rejected_by_the_string_parser() {
    // parse_document_claims keeps its one-string domain for other providers.
    let _ = parse_document_claims(audience_claims("\"aud\":[\"https://rp.example\"]"));
}
