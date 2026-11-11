//! Bounded parser for the direct-merchant WeChat Pay v3 transaction-query
//! response. It binds only top-level appid/mchid/trade_state/transaction_id/
//! attach, direct `payer.openid`, and `amount.total` plus CNY currency. The signed body is passed
//! unchanged to `verify_response` separately.
//!
//! Supported JSON is deliberately narrower than RFC 8259: unescaped UTF-8
//! strings with no control bytes, object keys of at most 32 bytes, unsigned
//! integer/bool/null scalars, and no fractions, exponents or negative numbers.
//! The response and the `payer`/`amount` objects are bound containers. Any
//! other object or array value (for example `scene_info` and
//! `promotion_detail` with `goods_detail`) is skipped: it is checked for
//! well-formed brackets, strings and separators, nests at most
//! `MAX_SKIPPED_DEPTH` deep, and its keys never bind a claim. A bound claim
//! key must carry its exact type: a string, an integer `amount.total`, or an
//! object `payer`/`amount`. Unsupported encodings fail closed.

/// The deepest nesting of skipped (unbound) containers. The documented
/// `promotion_detail[].goods_detail[]` needs four.
global MAX_SKIPPED_DEPTH: u32 = 8;

fn ws(c: u8) -> bool {
    (c == 32) | (c == 9) | (c == 10) | (c == 13)
}

/// Require exact response claims from the complete signed body. Expected byte
/// vectors are UTF-8 and bounded to 128 bytes. `expected_total` is CNY cents
/// (`amount.total` in the direct-merchant v3 query response).
pub fn assert_payment_claims<let N: u32>(
    body: BoundedVec<u8, N>,
    expected_appid: BoundedVec<u8, 128>,
    expected_mchid: BoundedVec<u8, 128>,
    expected_transaction_id: BoundedVec<u8, 128>,
    expected_openid: BoundedVec<u8, 128>,
    expected_attach: BoundedVec<u8, 128>,
    expected_total: u64,
) {
    assert((body.len() > 0) & (body.len() <= N));
    assert((expected_appid.len() > 0) & (expected_appid.len() <= 128));
    assert((expected_mchid.len() > 0) & (expected_mchid.len() <= 128));
    assert((expected_appid.len() <= 32) & (expected_mchid.len() <= 32));
    assert((expected_transaction_id.len() > 0) & (expected_transaction_id.len() <= 32));
    assert((expected_openid.len() > 0) & (expected_openid.len() <= 128));
    assert((expected_attach.len() > 0) & (expected_attach.len() <= 128));
    assert(expected_total > 0);
    assert_valid_utf8(body.storage(), body.len());

    // phase: 0 leading ws, 1 object expects key/end, 2 key bytes,
    // 3 colon, 4 value (or `]` directly after `[`), 5 string value,
    // 6 scalar token, 7 comma/end after a value, 8 trailing ws.
    // `depth` counts bound containers: 1 for the response, 2 inside
    // payer/amount. `skipped` counts the open skipped containers inside the
    // innermost bound one; bit 0 of `skipped_arrays` is 1 when the innermost
    // skipped container is an array (a stack of container kinds).
    let mut phase = 0;
    let mut depth = 0;
    let mut skipped: u32 = 0;
    let mut skipped_arrays: u32 = 0;
    let mut array_start = false; // the previous token was `[`
    let mut comma_pending = false; // the previous token was `,`
    let mut parent = 0; // 6=payer, 7=amount
    // 0 unbound, 1 appid, 2 mchid, 3 trade_state, 4 transaction_id,
    // 5 attach, 6 payer, 7 amount, 8 payer.openid, 9 amount.total,
    // 10 amount.currency. Invariant: target == 0 whenever skipped > 0, because
    // keys bind only when skipped == 0 and only target 0 opens a skipped
    // container; array elements have no key.
    let mut target = 0;
    let mut key_packed: Field = 0;
    let mut key_len = 0;
    let mut value_len = 0;
    // The first five scalar bytes, big-endian (enough for true, false, null).
    let mut token_packed: Field = 0;
    let mut token_len = 0;
    let mut token_digits = false;
    let mut token_zero_prefix = false;
    let mut number_value: u64 = 0;
    let mut seen_appid = false;
    let mut seen_mchid = false;
    let mut seen_state = false;
    let mut seen_transaction = false;
    let mut seen_attach = false;
    let mut seen_payer = false;
    let mut seen_openid = false;
    let mut seen_amount = false;
    let mut seen_total = false;
    let mut seen_currency = false;

    for i in 0..N {
        if i < body.len() {
            let c = body.storage()[i];
            // `c` follows a complete value (a separator or a container end).
            let mut after_value = false;
            // `c` closes the innermost open container.
            let mut close = false;
            if phase == 0 {
                if !ws(c) {
                    assert_eq(c, 123, "response must be an object");
                    depth = 1;
                    phase = 1;
                }
            } else if phase == 1 {
                if ws(c) {} else if c == 125 {
                    assert(!comma_pending, "trailing comma");
                    close = true;
                } else {
                    assert_eq(c, 34, "object key must be a string");
                    key_len = 0;
                    // Only the first 14 key bytes are packed: 112 bits < Fr.
                    // Length remains independently bounded to 32 bytes.
                    key_packed = 0;
                    comma_pending = false;
                    phase = 2;
                }
            } else if phase == 2 {
                if c == 34 {
                    target = 0;
                    if skipped == 0 {
                        if depth == 1 {
                            if key_is(key_packed, key_len, "appid") {
                                target = 1;
                            } else if key_is(key_packed, key_len, "mchid") {
                                target = 2;
                            } else if key_is(key_packed, key_len, "trade_state") {
                                target = 3;
                            } else if key_is(key_packed, key_len, "transaction_id") {
                                target = 4;
                            } else if key_is(key_packed, key_len, "attach") {
                                target = 5;
                            } else if key_is(key_packed, key_len, "payer") {
                                target = 6;
                            } else if key_is(key_packed, key_len, "amount") {
                                target = 7;
                            }
                        } else if (parent == 6) & key_is(key_packed, key_len, "openid") {
                            target = 8;
                        } else if (parent == 7) & key_is(key_packed, key_len, "total") {
                            target = 9;
                        } else if (parent == 7) & key_is(key_packed, key_len, "currency") {
                            target = 10;
                        }
                    }
                    phase = 3;
                } else {
                    assert((c >= 32) & (c != 92) & (key_len < 32), "unsupported object key");
                    if key_len < 14 {
                        key_packed = key_packed * 256 + c as Field;
                    }
                    key_len += 1;
                }
            } else if phase == 3 {
                if !ws(c) {
                    assert_eq(c, 58);
                    array_start = false;
                    phase = 4;
                }
            } else if phase == 4 {
                if ws(c) {} else if c == 93 {
                    // Only an empty array ends here; `[1,]` is rejected.
                    assert(array_start, "unexpected array end");
                    close = true;
                } else {
                    array_start = false;
                    comma_pending = false;
                    if c == 34 {
                        if target == 1 {
                            assert(!seen_appid, "duplicate appid");
                        }
                        if target == 2 {
                            assert(!seen_mchid, "duplicate mchid");
                        }
                        if target == 3 {
                            assert(!seen_state, "duplicate trade_state");
                        }
                        if target == 4 {
                            assert(!seen_transaction, "duplicate transaction_id");
                        }
                        if target == 5 {
                            assert(!seen_attach, "duplicate attach");
                        }
                        if target == 8 {
                            assert(!seen_openid, "duplicate payer.openid");
                        }
                        if target == 10 {
                            assert(!seen_currency, "duplicate amount.currency");
                        }
                        assert(
                            (target != 6) & (target != 7) & (target != 9),
                            "required claim must have expected type",
                        );
                        value_len = 0;
                        phase = 5;
                    } else if (c == 123) & ((target == 6) | (target == 7)) {
                        // Targets 6 and 7 bind only at depth 1 with nothing skipped.
                        if target == 6 {
                            assert(!seen_payer, "duplicate payer object");
                            seen_payer = true;
                        } else {
                            assert(!seen_amount, "duplicate amount object");
                            seen_amount = true;
                        }
                        parent = target;
                        depth = 2;
                        phase = 1;
                    } else if (c == 123) | (c == 91) {
                        // An object or array under an unbound key, or an
                        // element of a skipped array.
                        assert(target == 0, "required claim must have expected type");
                        assert(skipped < MAX_SKIPPED_DEPTH, "skipped value nested too deeply");
                        skipped_arrays = skipped_arrays * 2 + (c == 91) as u32;
                        skipped += 1;
                        if c == 123 {
                            phase = 1;
                        } else {
                            array_start = true;
                        }
                    } else {
                        assert(
                            (target != 1)
                                & (target != 2)
                                & (target != 3)
                                & (target != 4)
                                & (target != 5)
                                & (target != 6)
                                & (target != 7)
                                & (target != 8)
                                & (target != 10),
                            "required claim must have expected type",
                        );
                        assert((c != 125) & (c != 44) & (c != 58), "unexpected JSON token");
                        token_packed = c as Field;
                        token_len = 1;
                        token_digits = (c >= 48) & (c <= 57);
                        token_zero_prefix = c == 48;
                        number_value = 0;
                        if token_digits {
                            number_value = (c - 48) as u64;
                        }
                        phase = 6;
                    }
                }
            } else if phase == 5 {
                if c == 34 {
                    if target == 1 {
                        assert_eq(value_len, expected_appid.len());
                        seen_appid = true;
                    } else if target == 2 {
                        assert_eq(value_len, expected_mchid.len());
                        seen_mchid = true;
                    } else if target == 3 {
                        assert_eq(value_len, 7);
                        seen_state = true;
                    } else if target == 4 {
                        assert_eq(value_len, expected_transaction_id.len());
                        seen_transaction = true;
                    } else if target == 5 {
                        assert_eq(value_len, expected_attach.len());
                        seen_attach = true;
                    } else if target == 8 {
                        assert_eq(value_len, expected_openid.len());
                        seen_openid = true;
                    } else if target == 10 {
                        assert_eq(value_len, 3);
                        seen_currency = true;
                    }
                    phase = 7;
                } else {
                    assert((c >= 32) & (c != 92), "escaped/control string bytes unsupported");
                    if target == 1 {
                        assert(value_len < expected_appid.len());
                        assert_eq(c, expected_appid.storage()[value_len]);
                    } else if target == 2 {
                        assert(value_len < expected_mchid.len());
                        assert_eq(c, expected_mchid.storage()[value_len]);
                    } else if target == 3 {
                        assert(value_len < 7);
                        assert_eq(c, "SUCCESS".as_bytes()[value_len]);
                    } else if target == 4 {
                        assert(value_len < expected_transaction_id.len());
                        assert_eq(c, expected_transaction_id.storage()[value_len]);
                    } else if target == 5 {
                        assert(value_len < expected_attach.len());
                        assert_eq(c, expected_attach.storage()[value_len], "wrong attach");
                    } else if target == 8 {
                        assert(value_len < expected_openid.len());
                        assert_eq(c, expected_openid.storage()[value_len]);
                    } else if target == 10 {
                        assert(value_len < 3);
                        assert_eq(c, "CNY".as_bytes()[value_len], "wrong amount.currency");
                    }
                    value_len += 1;
                }
            } else if phase == 6 {
                if ws(c) | (c == 44) | (c == 125) | (c == 93) {
                    let bool_true = (token_len == 4) & (token_packed == 0x74727565);
                    let bool_false = (token_len == 5) & (token_packed == 0x66616c7365);
                    let null_value = (token_len == 4) & (token_packed == 0x6e756c6c);
                    assert(
                        token_digits | bool_true | bool_false | null_value,
                        "invalid/unsupported scalar",
                    );
                    if token_digits {
                        assert(!token_zero_prefix | (token_len == 1), "noncanonical integer");
                    }
                    if target == 9 {
                        assert(token_digits, "amount.total must be an unsigned integer");
                        assert_eq(number_value, expected_total, "wrong amount.total");
                        assert(!seen_total, "duplicate amount.total");
                        seen_total = true;
                    }
                    after_value = true;
                } else {
                    assert(token_len < N, "oversized scalar");
                    if token_len < 5 {
                        token_packed = token_packed * 256 + c as Field;
                    }
                    if (c < 48) | (c > 57) {
                        token_digits = false;
                    }
                    if token_digits {
                        assert(
                            number_value <= (18446744073709551615 - (c - 48) as u64) / 10,
                            "integer exceeds u64",
                        );
                        number_value = number_value * 10 + (c - 48) as u64;
                    }
                    token_len += 1;
                }
            } else if phase == 7 {
                after_value = true;
            } else {
                assert(ws(c), "trailing JSON bytes");
            }

            // One rule for what may follow any value, including a scalar
            // that ends directly at `,`, `}` or `]`.
            if after_value {
                if ws(c) {
                    phase = 7;
                } else if c == 44 {
                    comma_pending = true;
                    if (skipped_arrays & 1) == 1 {
                        array_start = false;
                        phase = 4;
                    } else {
                        phase = 1;
                    }
                } else {
                    assert((c == 125) | (c == 93), "invalid object separator");
                    close = true;
                }
            }

            // One rule for closing a container: a skipped one must close with
            // its own bracket kind; a bound one is an object.
            if close {
                if skipped > 0 {
                    assert_eq((skipped_arrays & 1) == 1, c == 93, "mismatched bracket");
                    skipped_arrays = skipped_arrays >> 1;
                    skipped -= 1;
                    phase = 7;
                } else {
                    assert_eq(c, 125, "mismatched bracket");
                    if depth == 1 {
                        phase = 8;
                    } else {
                        depth = 1;
                        phase = 7;
                    }
                }
            }
        }
    }

    assert((phase == 8) & (depth == 1) & (skipped == 0), "incomplete response object");
    assert(
        seen_appid & seen_mchid & seen_state & seen_transaction & seen_attach,
        "missing required payment claim",
    );
    assert(
        seen_payer & seen_openid & seen_amount & seen_total & seen_currency,
        "missing nested payer/amount claim",
    );
}

fn key_is<let K: u32>(key_packed: Field, len: u32, expected: str<K>) -> bool {
    let mut expected_packed: Field = 0;
    for i in 0..K {
        expected_packed = expected_packed * 256 + expected.as_bytes()[i] as Field;
    }
    (len == K) & (key_packed == expected_packed)
}

// UTF-8 scalar validation: rejects overlong forms, surrogates, values above
// U+10FFFF and truncated/isolated continuation bytes while allowing Chinese.
fn assert_valid_utf8<let N: u32>(bytes: [u8; N], len: u32) {
    let mut remaining = 0;
    let mut lower: u8 = 128;
    let mut upper: u8 = 191;
    for i in 0..N {
        if i < len {
            let c = bytes[i];
            if remaining > 0 {
                assert((c >= lower) & (c <= upper), "invalid UTF-8 continuation");
                remaining -= 1;
                lower = 128;
                upper = 191;
            } else if c < 128 {} else {
                assert((c >= 194) & (c <= 244), "invalid UTF-8 leading byte");
                remaining = if c < 224 {
                    1
                } else if c < 240 {
                    2
                } else {
                    3
                };
                lower = if c == 224 {
                    160
                } else if c == 240 {
                    144
                } else {
                    128
                };
                upper = if c == 237 {
                    159
                } else if c == 244 {
                    143
                } else {
                    191
                };
            }
        }
    }
    assert_eq(remaining, 0, "truncated UTF-8");
}

#[test]
fn parses_scoped_nested_payment_claims_and_utf8() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"用户-openid\"},\"amount\":{\"total\":2500,\"payer_total\":2500,\"currency\":\"CNY\"}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("用户-openid".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

// The body is otherwise complete, so only the missing payer.openid fails.
#[test(should_fail_with = "missing nested payer/amount claim")]
fn rejects_openid_from_wrong_parent() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"other\":{\"openid\":\"用户-openid\"},\"payer\":{},\"amount\":{\"total\":2500,\"currency\":\"CNY\"}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("用户-openid".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "duplicate payer.openid")]
fn rejects_duplicate_payer_openid() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"用户-openid\",\"openid\":\"用户-openid\"},\"amount\":{\"total\":2500}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("用户-openid".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "duplicate appid")]
fn rejects_duplicate_top_level_appid() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"test-openid-001\"},\"amount\":{\"total\":2500}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("test-openid-001".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "escaped/control string bytes unsupported")]
fn rejects_escaped_selected_value() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"test\\u002dopenid-001\"},\"amount\":{\"total\":2500}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("test-openid-001".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "wrong amount.currency")]
fn rejects_non_cny_amount_currency() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"test-openid-001\"},\"amount\":{\"total\":2500,\"currency\":\"USD\"}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("test-openid-001".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "duplicate amount.currency")]
fn rejects_duplicate_amount_currency() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"payer\":{\"openid\":\"test-openid-001\"},\"amount\":{\"total\":2500,\"currency\":\"CNY\",\"currency\":\"CNY\"}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("test-openid-001".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "wrong attach")]
fn rejects_wrong_action_attach() {
    let body: BoundedVec<u8, 512> = BoundedVec::from_array(
        "{\"appid\":\"wx123456\",\"mchid\":\"1900000001\",\"trade_state\":\"SUCCESS\",\"transaction_id\":\"4200000000202410100000000001\",\"attach\":\"other-action\",\"payer\":{\"openid\":\"用户-openid\"},\"amount\":{\"total\":2500}}"
            .as_bytes(),
    );
    assert_payment_claims(
        body,
        BoundedVec::from_array("wx123456".as_bytes()),
        BoundedVec::from_array("1900000001".as_bytes()),
        BoundedVec::from_array("4200000000202410100000000001".as_bytes()),
        BoundedVec::from_array("用户-openid".as_bytes()),
        BoundedVec::from_array("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "invalid UTF-8 continuation")]
fn rejects_malformed_utf8() {
    assert_valid_utf8([237, 160, 128], 3);
}
