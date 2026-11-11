//! Bounded structured JSON for signed metadata. Unescaped strings <=4096 bytes,
//! nesting <=8, unsigned canonical u64/bool/null scalar profile.
use crate::json_profile::{nested_byte, nested_start};
pub struct JsonSpan {
    pub start: u32,
    pub end: u32,
    pub kind: u8,
}
fn ws(b: u8) -> bool {
    (b == 32) | (b == 9) | (b == 10) | (b == 13)
}
pub fn assert_json_document<let N: u32>(input: BoundedVec<u8, N>) -> JsonSpan {
    crate::json::assert_valid_utf8(input.storage(), input.len());
    let mut state = nested_start();
    let mut started = false;
    let mut start = 0;
    let mut end = 0;
    for i in 0..N {
        if i < input.len() {
            let b = input.storage()[i];
            if !started {
                if !ws(b) {
                    assert(b == 123, "JSON document must be object");
                    started = true;
                    start = i;
                }
            } else if !state.done {
                state = nested_byte(state, b);
                if state.done {
                    end = i + 1;
                }
            } else {
                assert(ws(b), "trailing JSON document bytes");
            }
        }
    }
    assert(started & state.done, "incomplete JSON document");
    JsonSpan { start, end, kind: 123 }
}
/// Locate an exact direct object member. The document must first be validated.
/// Span must derive from the document root or a preceding member/array result.
/// Duplicate selected members fail, including an earlier value of another type.
pub fn json_member<let N: u32, let K: u32>(
    input: BoundedVec<u8, N>,
    object: JsonSpan,
    name: str<K>,
) -> JsonSpan {
    let (span, present) = json_optional_member(input, object, name);
    assert(present, "missing selected JSON member");
    span
}
pub fn json_optional_member<let N: u32, let K: u32>(
    input: BoundedVec<u8, N>,
    object: JsonSpan,
    name: str<K>,
) -> (JsonSpan, bool) {
    assert((object.start < object.end) & (object.end <= input.len()));
    assert(
        (object.kind == 123)
            & (input.storage()[object.start] == 123)
            & (input.storage()[object.end - 1] == 125),
        "JSON member requires object",
    );
    let mut depth = 0;
    let mut quoted = false;
    let mut key_expected = true;
    let mut is_key = false;
    let mut quote_start = 0;
    let mut selected = false;
    let mut after_colon = false;
    let mut count = 0;
    let mut result = JsonSpan { start: 0, end: 0, kind: 0 };
    let mut active = false;
    for i in 0..N {
        if (i >= object.start) & (i < object.end) {
            let b = input.storage()[i];
            if quoted {
                if b == 34 {
                    quoted = false;
                    if is_key {
                        let mut same = i - quote_start == K;
                        for j in 0..K {
                            if j < i - quote_start {
                                same =
                                    same & (input.storage()[quote_start + j] == name.as_bytes()[j]);
                            }
                        }
                        selected = same;
                        if same {
                            count += 1;
                            assert(count == 1, "duplicate selected JSON member");
                        }
                    } else if (depth == 1) & active {
                        result.end = i + 1;
                        active = false;
                    }
                }
            } else if b == 34 {
                quoted = true;
                is_key = (depth == 1) & key_expected;
                quote_start = i + 1;
                if (depth == 1) & after_colon {
                    after_colon = false;
                    if selected {
                        result = JsonSpan { start: i, end: 0, kind: b };
                        active = true;
                    }
                }
            } else if (b == 123) | (b == 91) {
                if (depth == 1) & after_colon {
                    after_colon = false;
                    if selected {
                        result = JsonSpan { start: i, end: 0, kind: b };
                        active = true;
                    }
                }
                depth += 1;
            } else if (b == 125) | (b == 93) {
                if (depth == 1) & active {
                    active = false;
                }
                depth -= 1;
                if (depth == 1) & active {
                    result.end = i + 1;
                    active = false;
                }
            } else if depth == 1 {
                if b == 58 {
                    key_expected = false;
                    after_colon = true;
                } else if b == 44 {
                    active = false;
                    key_expected = true;
                    after_colon = false;
                    selected = false;
                } else if !ws(b) {
                    if after_colon {
                        after_colon = false;
                        if selected {
                            result = JsonSpan { start: i, end: i + 1, kind: b };
                            active = true;
                        }
                    } else if active {
                        result.end = i + 1;
                    }
                }
            }
        }
    }
    assert((count == 0) | (result.end > result.start), "incomplete selected JSON member");
    (result, count == 1)
}
pub fn json_string<let N: u32, let OUT: u32>(
    input: BoundedVec<u8, N>,
    span: JsonSpan,
) -> BoundedVec<u8, OUT> {
    assert((span.kind == 34) & (span.end >= span.start + 2), "JSON member must be string");
    assert(span.end <= input.len());
    let len = span.end - span.start - 2;
    assert(len <= OUT, "JSON string exceeds capacity");
    let mut out = BoundedVec::<u8, OUT>::new();
    for i in 0..OUT {
        if i < len {
            out.push(input.storage()[span.start + 1 + i]);
        }
    }
    out
}
pub fn json_u64<let N: u32>(input: BoundedVec<u8, N>, span: JsonSpan) -> u64 {
    assert(span.end <= input.len());
    assert((span.end > span.start) & (span.end - span.start <= 20), "JSON integer exceeds u64");
    let mut out = 0u64;
    for i in 0..20 {
        if i < span.end - span.start {
            let b = input.storage()[span.start + i];
            assert((b >= 48) & (b <= 57), "JSON member must be unsigned integer");
            out = out * 10 + (b - 48) as u64;
        }
    }
    out
}
/// Extract a selected element and enforce a bounded array cardinality.
/// Scalar spans contain no trailing whitespace. Caller validates the document.
pub fn json_array_element<let N: u32>(
    input: BoundedVec<u8, N>,
    array: JsonSpan,
    index: u32,
    max_items: u32,
) -> (JsonSpan, bool) {
    assert((array.start < array.end) & (array.end <= input.len()));
    assert(
        (array.kind == 91)
            & (input.storage()[array.start] == 91)
            & (input.storage()[array.end - 1] == 93),
        "JSON value must be array",
    );
    let mut depth = 0;
    let mut quoted = false;
    let mut count = 0;
    let mut waiting = true;
    let mut active = false;
    let mut result = JsonSpan { start: 0, end: 0, kind: 0 };
    for i in 0..N {
        if (i >= array.start) & (i < array.end) {
            let b = input.storage()[i];
            if quoted {
                if b == 34 {
                    quoted = false;
                    if (depth == 1) & active {
                        result.end = i + 1;
                        active = false;
                    }
                }
            } else {
                if (depth == 1) & waiting & !ws(b) & (b != 93) {
                    if count == index {
                        result = JsonSpan { start: i, end: i + 1, kind: b };
                        active = true;
                    }
                    count += 1;
                    waiting = false;
                }
                if b == 34 {
                    quoted = true;
                } else if (b == 123) | (b == 91) {
                    depth += 1;
                } else if (b == 125) | (b == 93) {
                    if (depth == 1) & active {
                        active = false;
                    }
                    depth -= 1;
                    if (depth == 1) & active {
                        result.end = i + 1;
                        active = false;
                    }
                } else if depth == 1 {
                    if b == 44 {
                        waiting = true;
                        active = false;
                    } else if active & !ws(b) {
                        result.end = i + 1;
                    }
                }
            }
        }
    }
    assert(count <= max_items, "JSON array exceeds profile");
    (result, index < count)
}
#[test]
fn structured_path_and_array() {
    let input = crate::literal_vec(
        "{\"metadata\":{\"op\":{\"keys\":[{\"n\":\"first\"},{\"n\":\"second\"}]}},\"exp\":123}",
    );
    let root = assert_json_document(input);
    let metadata = json_member(input, root, "metadata");
    let op = json_member(input, metadata, "op");
    let keys = json_member(input, op, "keys");
    let (item, present) = json_array_element(input, keys, 1, 8);
    assert(present);
    let n = json_string::<256, 6>(input, json_member(input, item, "n"));
    assert(n.storage() == "second".as_bytes());
    assert(json_u64(input, json_member(input, root, "exp")) == 123);
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn duplicate_container_rejected() {
    let data = crate::literal_vec("{\"metadata\":{},\"metadata\":{}}");
    let root = assert_json_document(data);
    let _x = json_member(data, root, "metadata");
}
#[test(should_fail_with = "missing selected JSON member")]
fn nested_cannot_shadow_root() {
    let data = crate::literal_vec("{\"wrapper\":{\"iss\":\"evil\"}}");
    let root = assert_json_document(data);
    let _x = json_member(data, root, "iss");
}
#[test(should_fail_with = "trailing comma in nested JSON")]
fn malformed_nested_rejected() {
    let _r = assert_json_document(crate::literal_vec("{\"a\":[1,]}"));
}
#[test]
fn optional_member_and_array_scalars() {
    let data = crate::literal_vec("{\"a\":[\"x\",7,true,{\"a\":\"inner\"}]}");
    let root = assert_json_document(data);
    let (_, exists) = json_optional_member(data, root, "missing");
    assert(!exists);
    let array = json_member(data, root, "a");
    let (n, present) = json_array_element(data, array, 1, 4);
    assert(present);
    assert(json_u64(data, n) == 7);
    let (_, outside) = json_array_element(data, array, 4, 4);
    assert(!outside);
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn selected_type_shadowing_rejected() {
    let data = crate::literal_vec("{\"iss\":null,\"iss\":\"good\"}");
    let root = assert_json_document(data);
    let _x = json_member(data, root, "iss");
}

// Regression coverage retained from a rejected key-buffer optimization.
// Exact selected-name length, unknown prefixes and empty names remain supported.
#[test]
fn member_buffer_empty_prefix_and_scope() {
    let data = crate::literal_vec(
        "{\"\":7,\"issuer\":\"long\",\"is\":\"short\",\"wrapper\":{\"iss\":\"nested\"},\"iss\":\"right\"}",
    );
    let root = assert_json_document(data);
    assert(json_u64(data, json_member(data, root, "")) == 7);
    let result = json_string::<256, 5>(data, json_member(data, root, "iss"));
    assert(result.storage() == "right".as_bytes());
    let (_, missing) = json_optional_member(data, root, "issuer-longer-than-every-key");
    assert(!missing);
}
#[test]
fn member_buffer_long_unknown_key() {
    let data = crate::literal_vec(
        "{\"issxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\":null,\"iss\":\"good\"}",
    );
    let root = assert_json_document(data);
    let selected = json_string::<256, 4>(data, json_member(data, root, "iss"));
    assert(selected.storage() == "good".as_bytes());
}
#[test(should_fail_with = "duplicate selected JSON member")]
fn member_buffer_empty_duplicate() {
    let data = crate::literal_vec("{\"\":null,\"\":{}}");
    let root = assert_json_document(data);
    let _selected = json_member(data, root, "");
}

#[test(should_fail_with = "JSON document must be object")]
fn bom_signed_document_rejected() {
    let mut input = BoundedVec::<u8, 8>::from_array([239, 187, 191]);
    input.push(123);
    input.push(125);
    let _ = assert_json_document(input);
}
#[test(should_fail_with = "JSON member must be string")]
fn singleton_acr_array_is_not_a_string() {
    let data = crate::literal_vec("{\"acr\":[\"urn:singpass:authentication:loa:2\"]}");
    let root = assert_json_document(data);
    let _ = json_string::<256, 64>(data, json_member(data, root, "acr"));
}
#[test]
fn string_acr_remains_supported() {
    let data = crate::literal_vec("{\"acr\":\"urn:singpass:authentication:loa:2\"}");
    let root = assert_json_document(data);
    let actual = json_string::<256, 64>(data, json_member(data, root, "acr"));
    assert(actual.len() == 33);
}
