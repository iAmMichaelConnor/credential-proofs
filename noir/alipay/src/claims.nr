//! Bounded flat-response profile. Byte-exact UTF-8 strings, unsigned integers,
//! booleans and null are accepted. Escapes and nested values are unsupported.

fn ws(c: u8) -> bool {
    (c == 32) | (c == 9) | (c == 10) | (c == 13)
}

/// Bind one unique top-level string claim to the complete signed body. Call
/// this on the SAME body passed to verify_v2_signed_body/verify_v3_response.
pub fn assert_string_claim<let N: u32, let K: u32, let V: u32>(
    body: BoundedVec<u8, N>,
    key: str<K>,
    expected: BoundedVec<u8, V>,
) {
    assert(body.len() <= N);
    assert((expected.len() > 0) & (expected.len() <= V));
    assert_valid_utf8(body.storage(), body.len());
    let mut phase = 0;
    let mut key_len = 0;
    let mut key_matches = true;
    let mut target = false;
    let mut value_len = 0;
    let mut seen = false;
    let mut after_comma = false;
    let mut scalar = [0; 5];
    let mut digits = true;
    for i in 0..N {
        if i < body.len() {
            let c = body.storage()[i];
            if phase == 0 {
                if !ws(c) {
                    assert_eq(c, 123);
                    phase = 1;
                }
            } else if phase == 1 {
                if ws(c) {} else if c == 125 {
                    assert(!after_comma, "trailing comma");
                    phase = 8;
                } else {
                    assert_eq(c, 34);
                    key_len = 0;
                    key_matches = true;
                    after_comma = false;
                    phase = 2;
                }
            } else if phase == 2 {
                if c == 34 {
                    target = key_matches & (key_len == K);
                    phase = 3;
                } else {
                    assert((c >= 32) & (c != 92), "unsupported key encoding");
                    if key_len < K {
                        key_matches &= c == key.as_bytes()[key_len];
                    }
                    key_len += 1;
                }
            } else if phase == 3 {
                if !ws(c) {
                    assert_eq(c, 58);
                    phase = 4;
                }
            } else if phase == 4 {
                if ws(c) {} else if c == 34 {
                    value_len = 0;
                    phase = 5;
                } else {
                    assert(!target, "expected claim must be a string");
                    assert((c != 123) & (c != 91), "nested response unsupported");
                    scalar = [c, 0, 0, 0, 0];
                    value_len = 1;
                    digits = (c >= 48) & (c <= 57);
                    phase = 6;
                }
            } else if phase == 5 {
                if c == 34 {
                    if target {
                        assert(!seen, "duplicate expected claim");
                        assert_eq(value_len, expected.len(), "wrong claim length");
                        seen = true;
                    }
                    phase = 7;
                } else {
                    assert((c >= 32) & (c != 92), "unsupported string encoding");
                    if target {
                        assert(value_len < expected.len(), "wrong claim length");
                        assert_eq(c, expected.storage()[value_len], "wrong claim value");
                    }
                    value_len += 1;
                }
            } else if phase == 6 {
                if ws(c) | (c == 44) | (c == 125) {
                    let number = digits & ((value_len == 1) | (scalar[0] != 48));
                    let boolean = ((value_len == 4) & (scalar == [116, 114, 117, 101, 0]))
                        | ((value_len == 5) & (scalar == [102, 97, 108, 115, 101]));
                    let null_value = (value_len == 4) & (scalar == [110, 117, 108, 108, 0]);
                    assert(number | boolean | null_value, "invalid JSON scalar");
                    if ws(c) {
                        phase = 7;
                    } else if c == 44 {
                        phase = 1;
                        after_comma = true;
                    } else {
                        phase = 8;
                    }
                } else {
                    if value_len < 5 {
                        scalar[value_len] = c;
                    }
                    digits &= (c >= 48) & (c <= 57);
                    value_len += 1;
                }
            } else if phase == 7 {
                if ws(c) {} else if c == 44 {
                    phase = 1;
                    after_comma = true;
                } else {
                    assert_eq(c, 125, "invalid separator");
                    phase = 8;
                }
            } else {
                assert(ws(c), "trailing response data");
            }
        }
    }
    assert((phase == 8) & seen, "missing claim or incomplete response");
}

/// The trade-query profile (`alipay.trade.query`, used by payment
/// settlement). Binds, in the same flat signed body, unique top-level
/// strings `trade_no` and `out_trade_no` equal to the expected values,
/// `trade_status == "TRADE_SUCCESS"`, and `total_amount` equal to the
/// canonical yuan text of `expected_total_fen` (`"25.00"`: no leading zero
/// except `"0.01"`, exactly two decimals). The flat-body profile rejects
/// responses with nested values (for example `fund_bill_list`). The response
/// names no seller: the caller must take the payee from its trust in the key.
/// Call this on the SAME body passed to `verify_v3_response`.
pub fn assert_trade_query_claims<let N: u32>(
    body: BoundedVec<u8, N>,
    expected_trade_no: BoundedVec<u8, 64>,
    expected_out_trade_no: BoundedVec<u8, 64>,
    expected_total_fen: u64,
) {
    assert(expected_total_fen > 0, "zero trade amount");
    assert_string_claim(body, "trade_no", expected_trade_no);
    assert_string_claim(body, "out_trade_no", expected_out_trade_no);
    assert_string_claim(
        body,
        "trade_status",
        BoundedVec::<u8, 13>::from_array("TRADE_SUCCESS".as_bytes()),
    );
    assert_string_claim(body, "total_amount", yuan_text(expected_total_fen));
}

/// Canonical Alipay amount text of a positive amount in fen: the yuan digits
/// without leading zeros (`"0"` below one yuan), a dot and two fen digits.
pub fn yuan_text(fen: u64) -> BoundedVec<u8, 24> {
    let yuan = fen / 100;
    let cents = fen % 100;
    let mut digits = [0; 20];
    let mut count = 0;
    let mut rest = yuan;
    for i in 0..20 {
        if (i == 0) | (rest != 0) {
            digits[i] = (rest % 10) as u8 + 48;
            rest = rest / 10;
            count = i + 1;
        }
    }
    let mut out = [0; 24];
    for i in 0..20 {
        if i < count {
            out[i] = digits[count - 1 - i];
        }
    }
    out[count] = 46;
    out[count + 1] = (cents / 10) as u8 + 48;
    out[count + 2] = (cents % 10) as u8 + 48;
    BoundedVec::from_parts(out, count + 3)
}

// Same UTF-8 scalar-value bounds as the OIDC profile. Chinese text remains
// byte-exact; overlong encodings, surrogate codepoints and truncation fail.
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
fn chinese_identity_and_other_scalars() {
    let body: BoundedVec<u8, 128> = BoundedVec::from_array(
        "{\"nick_name\":\"测试用户\",\"active\":true,\"extra\":null,\"age\":25,\"user_id\":\"2088\"}"
            .as_bytes(),
    );
    assert_string_claim(
        body,
        "user_id",
        BoundedVec::<u8, 4>::from_array("2088".as_bytes()),
    );
}

#[test(should_fail_with = "duplicate expected claim")]
fn reject_duplicate_identity() {
    let body: BoundedVec<u8, 128> =
        BoundedVec::from_array("{\"user_id\":\"2088\",\"user_id\":\"2088\"}".as_bytes());
    assert_string_claim(
        body,
        "user_id",
        BoundedVec::<u8, 4>::from_array("2088".as_bytes()),
    );
}

#[test(should_fail_with = "nested response unsupported")]
fn reject_nested_identity() {
    let body: BoundedVec<u8, 128> =
        BoundedVec::from_array("{\"extra\":{\"user_id\":\"2088\"}}".as_bytes());
    assert_string_claim(
        body,
        "user_id",
        BoundedVec::<u8, 4>::from_array("2088".as_bytes()),
    );
}

#[test(should_fail_with = "wrong claim value")]
fn reject_wrong_identity() {
    let body: BoundedVec<u8, 128> = BoundedVec::from_array("{\"user_id\":\"2088\"}".as_bytes());
    assert_string_claim(
        body,
        "user_id",
        BoundedVec::<u8, 4>::from_array("2089".as_bytes()),
    );
}

#[test(should_fail_with = "invalid UTF-8 continuation")]
fn reject_malformed_utf8() {
    assert_valid_utf8([237, 160, 128], 3);
}

#[test]
fn yuan_text_is_canonical() {
    assert_eq(yuan_text(2500), BoundedVec::<u8, 24>::from_array("25.00".as_bytes()));
    assert_eq(yuan_text(1), BoundedVec::<u8, 24>::from_array("0.01".as_bytes()));
    assert_eq(yuan_text(100), BoundedVec::<u8, 24>::from_array("1.00".as_bytes()));
    assert_eq(yuan_text(1234567), BoundedVec::<u8, 24>::from_array("12345.67".as_bytes()));
    assert_eq(
        yuan_text(18446744073709551615),
        BoundedVec::<u8, 24>::from_array("184467440737095516.15".as_bytes()),
    );
}

#[test]
fn trade_query_profile_accepts_a_successful_trade() {
    let body: BoundedVec<u8, 256> = BoundedVec::from_array(
        "{\"trade_no\":\"2026\",\"out_trade_no\":\"ab12\",\"buyer_logon_id\":\"159****0000\",\"trade_status\":\"TRADE_SUCCESS\",\"total_amount\":\"25.00\"}"
            .as_bytes(),
    );
    assert_trade_query_claims(
        body,
        BoundedVec::from_array("2026".as_bytes()),
        BoundedVec::from_array("ab12".as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "wrong claim value")]
fn trade_query_profile_rejects_an_unpaid_trade() {
    let body: BoundedVec<u8, 256> = BoundedVec::from_array(
        "{\"trade_no\":\"2026\",\"out_trade_no\":\"ab12\",\"trade_status\":\"TRADE_CLOSED\",\"total_amount\":\"25.00\"}"
            .as_bytes(),
    );
    assert_trade_query_claims(
        body,
        BoundedVec::from_array("2026".as_bytes()),
        BoundedVec::from_array("ab12".as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "wrong claim length")]
fn trade_query_profile_rejects_a_noncanonical_amount() {
    let body: BoundedVec<u8, 256> = BoundedVec::from_array(
        "{\"trade_no\":\"2026\",\"out_trade_no\":\"ab12\",\"trade_status\":\"TRADE_SUCCESS\",\"total_amount\":\"25.0\"}"
            .as_bytes(),
    );
    assert_trade_query_claims(
        body,
        BoundedVec::from_array("2026".as_bytes()),
        BoundedVec::from_array("ab12".as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "missing claim or incomplete response")]
fn trade_query_profile_rejects_a_missing_status() {
    let body: BoundedVec<u8, 256> = BoundedVec::from_array(
        "{\"trade_no\":\"2026\",\"out_trade_no\":\"ab12\",\"total_amount\":\"25.00\"}".as_bytes(),
    );
    assert_trade_query_claims(
        body,
        BoundedVec::from_array("2026".as_bytes()),
        BoundedVec::from_array("ab12".as_bytes()),
        2500,
    );
}

#[test(should_fail_with = "nested response unsupported")]
fn trade_query_profile_rejects_nested_values() {
    let body: BoundedVec<u8, 256> = BoundedVec::from_array(
        "{\"trade_no\":\"2026\",\"out_trade_no\":\"ab12\",\"trade_status\":\"TRADE_SUCCESS\",\"total_amount\":\"25.00\",\"fund_bill_list\":[]}"
            .as_bytes(),
    );
    assert_trade_query_claims(
        body,
        BoundedVec::from_array("2026".as_bytes()),
        BoundedVec::from_array("ab12".as_bytes()),
        2500,
    );
}
