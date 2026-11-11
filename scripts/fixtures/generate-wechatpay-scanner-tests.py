#!/usr/bin/env python3
"""Generate the WeChat Pay claims-scanner regression tests.

The tests cover a nested object that ends with a scalar,
a non-string amount.currency and unbound objects and arrays (such
as scene_info and promotion_detail, and the 1024-byte body cap). Bodies are
built here with json.dumps over the documented JSAPI query-response shape
(https://pay.wechatpay.cn/doc/v3/merchant/4012791858), or as small edits of a
base response. They are synthetic and carry no signature: the RSA path is
tested by the WeChat Pay known-answer test (noir/wechatpay/src/known_answer_tests.nr).

Output: noir/wechatpay/src/scanner_tests.nr

Each case compiles the whole 1024-byte scanner, so a test costs about 45 s
and 3 GB. The top level holds one positive test per finding and one negative
test per named check (FAST below); the `scanner_tests::variants` module holds
positive variants and further rejections of a check that a top-level test
already covers.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generated_noir import ROOT, emit  # noqa: E402

PACKAGE = ROOT / "noir/wechatpay"
NOIR_OUT = PACKAGE / "src/scanner_tests.nr"
# The body capacity of the consumers (the wechatpay_v3_response benchmark and the
# payment-settlement adapter).
CAPACITY = 1024

ATT = "0123456789abcdef" * 4
TOP = {
    "appid": "wx123456",
    "mchid": "1900000001",
    "trade_state": "SUCCESS",
    "transaction_id": "4200000000202410100000000001",
    "attach": ATT,
}
PAYER = {"openid": "test-openid-001"}


def compact(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def lit(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


cases = []  # (name, comment, body, expected total, should_fail_with or None)

# The top-level cases (every other case is in `scanner_tests::variants`).
# Positive: the scalar-close shape and the full documented response.
# Negative: one case per named check of the scanner, by the assert that it
# reaches ("required claim must have expected type" has three asserts: a string
# for an object or integer claim, a container for a claim, and a scalar for a
# claim; "mismatched bracket" has two: skipped arrays and bound objects). The
# duplicate and wrong-value checks of the scalar claims are in claims.nr.
FAST = {
    "accepts_amount_ending_in_total_without_whitespace",
    "accepts_full_documented_response_with_coupon_and_scene_info",
    "rejects_wrong_total_when_total_ends_amount",
    "rejects_duplicate_total_ending_amount",
    "rejects_duplicate_amount_after_scalar_close",
    "rejects_trailing_nested_comma_after_scalar",
    "rejects_missing_top_close_after_scalar_close",
    "rejects_numeric_currency_before_cny",
    "rejects_appid_only_inside_skipped_array",
    "rejects_nine_skipped_levels",
    "rejects_array_closed_by_brace",
    "rejects_bound_object_closed_by_bracket",
    "rejects_trailing_comma_in_skipped_array",
    "rejects_leading_comma_in_skipped_array",
    "rejects_key_in_skipped_array",
    "rejects_escape_inside_skipped_string",
    "rejects_string_total",
    "rejects_currency_array",
}


def add(name, comment, body, total=2500, fail=None):
    cases.append((name, comment, body, total, fail))


# The base response without its amount object, ready for a raw amount suffix.
HEAD = compact({**TOP, "payer": PAYER})[:-1] + ',"amount":'

# A nested object may end directly after a scalar.
add(
    "accepts_amount_ending_in_total_without_whitespace",
    "Amount may end directly after its integer total.",
    HEAD + '{"currency":"CNY","total":100}}',
    total=100,
)
add(
    "accepts_amount_ending_in_max_u64_total",
    "The largest u64 total may end the amount object.",
    HEAD + '{"currency":"CNY","total":18446744073709551615}}',
    total=18446744073709551615,
)
add(
    "accepts_payer_ending_in_unknown_null",
    "An unknown null member may end the payer object.",
    compact(
        {
            **TOP,
            "payer": {**PAYER, "x": None},
            "amount": {"total": 2500, "currency": "CNY"},
        }
    ),
)
add(
    "accepts_payer_ending_in_unknown_true",
    "An unknown true member may end the payer object.",
    compact(
        {
            **TOP,
            "payer": {**PAYER, "x": True},
            "amount": {"total": 2500, "currency": "CNY"},
        }
    ),
)
add(
    "accepts_alphabetical_key_order_without_whitespace",
    "Alphabetical order ends amount with total; later keys are top-level.",
    compact(
        dict(
            sorted(
                {
                    **TOP,
                    "payer": PAYER,
                    "amount": {
                        "currency": "CNY",
                        "payer_currency": "CNY",
                        "payer_total": 2500,
                        "total": 2500,
                    },
                }.items()
            )
        )
    ),
)
add(
    "accepts_top_level_total_and_currency_after_scalar_close",
    "After a scalar close, total/currency keys are unbound top-level keys.",
    HEAD + '{"currency":"CNY","total":2500},"currency":840,"total":"x"}',
)
add(
    "accepts_top_level_body_ending_in_scalar",
    "A depth-1 object may still end directly after a scalar.",
    HEAD + '{"total":2500,"currency":"CNY"},"z":1}',
)
add(
    "rejects_wrong_total_when_total_ends_amount",
    "The total check still runs when total ends the amount object.",
    HEAD + '{"currency":"CNY","total":2500}}',
    total=2501,
    fail="wrong amount.total",
)
add(
    "rejects_duplicate_total_ending_amount",
    "A repeated total that ends the amount object is still rejected.",
    HEAD + '{"total":2500,"currency":"CNY","total":2500}}',
    fail="duplicate amount.total",
)
add(
    "rejects_duplicate_amount_after_scalar_close",
    "A second amount object after a scalar close is rejected.",
    HEAD + '{"currency":"CNY","total":2500},"amount":{"currency":"CNY"}}',
    fail="duplicate amount object",
)
add(
    "rejects_trailing_nested_comma_after_scalar",
    "A comma after the last scalar still needs another member.",
    HEAD + '{"currency":"CNY","total":2500,}}',
    fail="trailing comma",
)
add(
    "rejects_missing_top_close_after_scalar_close",
    "A scalar close of amount does not also close the response.",
    HEAD + '{"currency":"CNY","total":2500}',
    fail="incomplete response object",
)

# Amount.currency must be a string, so no non-string duplicate passes.
add(
    "rejects_numeric_currency_before_cny",
    "A numeric amount.currency is rejected even with a later CNY.",
    HEAD + '{"total":2500,"currency":840,"currency":"CNY"}}',
    fail="required claim must have expected type",
)
add(
    "rejects_null_currency_after_cny",
    "A null amount.currency after CNY is rejected.",
    HEAD + '{"total":2500,"currency":"CNY","currency":null,"payer_currency":"CNY"}}',
    fail="required claim must have expected type",
)
add(
    "rejects_null_currency_alone",
    "A null amount.currency is not a currency.",
    HEAD + '{"currency":null,"total":2500,"payer_currency":"CNY"}}',
    fail="required claim must have expected type",
)
add(
    "rejects_bool_currency_ending_amount",
    "A scalar duplicate currency that ends amount is rejected.",
    HEAD + '{"total":2500,"currency":"CNY","currency":true}}',
    fail="required claim must have expected type",
)

# Full documented query response: every documented member, a coupon with
# goods_detail and scene_info. Over 512 bytes compact.
FULL = {
    "appid": "wx123456",
    "mchid": "1900000001",
    "out_trade_no": "1217752501201407033233368018",
    "transaction_id": "4200000000202410100000000001",
    "trade_type": "JSAPI",
    "trade_state": "SUCCESS",
    "trade_state_desc": "\u652f\u4ed8\u6210\u529f",
    "bank_type": "CMC",
    "attach": ATT,
    "success_time": "2018-06-08T10:34:56+08:00",
    "payer": {"openid": "test-openid-001"},
    "amount": {
        "total": 2500,
        "payer_total": 2400,
        "currency": "CNY",
        "payer_currency": "CNY",
    },
    "scene_info": {"device_id": "013467007045764"},
    "promotion_detail": [
        {
            "coupon_id": "109519",
            "name": "\u5355\u54c1\u60e0-6",
            "scope": "SINGLE",
            "type": "CASH",
            "amount": 100,
            "stock_id": "931386",
            "wechatpay_contribute": 0,
            "merchant_contribute": 100,
            "other_contribute": 0,
            "currency": "CNY",
            "goods_detail": [
                {
                    "goods_id": "M1006",
                    "quantity": 1,
                    "unit_price": 2500,
                    "discount_amount": 100,
                    "goods_remark": "\u5546\u54c1\u5907\u6ce8\u4fe1\u606f",
                }
            ],
        }
    ],
}

MIN = {**TOP, "payer": PAYER, "amount": {"total": 2500, "currency": "CNY"}}


full = compact(FULL)
assert 512 < len(full.encode()) <= 1024, len(full.encode())
add(
    "accepts_full_documented_response_with_coupon_and_scene_info",
    "The full documented response with scene_info and a coupon (promotion_detail with goods_detail).",
    full,
)
# The pretty-printed full response with goods_detail is 1149 bytes, over the
# 1024-byte cap; without goods_detail it fits.
PRETTY = {
    **FULL,
    "promotion_detail": [
        {k: v for k, v in FULL["promotion_detail"][0].items() if k != "goods_detail"}
    ],
}
pretty = json.dumps(PRETTY, ensure_ascii=False, indent=2)
assert len(pretty.encode()) <= 1024, len(pretty.encode())
add(
    "accepts_pretty_printed_full_response",
    "A pretty-printed response with scene_info and a coupon: whitespace inside skipped containers.",
    pretty,
)
add(
    "accepts_empty_promotion_detail_and_scene_info_object",
    "An empty array and an unbound object at the top level.",
    compact(
        {**MIN, "promotion_detail": [], "scene_info": {"device_id": "013467007045764"}}
    ),
)
add(
    "accepts_skipped_strings_with_brackets_and_claim_names",
    "Brackets and claim-like text inside skipped strings do not end the skipped container.",
    compact(
        {
            **MIN,
            "promotion_detail": [
                {"name": ']},"amount":{"total":1}', "x": ["}", "[", "{"]}
            ],
        }
    ).replace('\\"', "'"),
)
add(
    "accepts_skipped_object_inside_amount",
    "An unbound object or array inside amount is skipped, and its total is ignored.",
    compact(
        {
            **TOP,
            "payer": PAYER,
            "amount": {
                "detail": {"total": 1, "currency": "USD"},
                "list": [[], [1, 2]],
                "total": 2500,
                "currency": "CNY",
            },
        }
    ),
)
add(
    "accepts_eight_skipped_levels",
    "Skipped containers may nest MAX_SKIPPED_DEPTH = 8 deep.",
    compact({**MIN, "x": [[[[[[[[]]]]]]]]}),
)
add(
    "accepts_claim_keys_inside_skipped_containers_without_binding",
    "Appid/payer keys inside a skipped container do not bind or count as duplicates.",
    compact(
        {
            **MIN,
            "scene_info": {
                "appid": "other",
                "payer": {"openid": "other"},
                "amount": {"total": 1},
            },
        }
    ),
)

# Negative cases: each must fail in the constraint named.
add(
    "rejects_openid_only_inside_skipped_object",
    "A payer object inside a skipped container is not the payer.",
    compact(
        {
            **TOP,
            "scene_info": {"payer": {"openid": "test-openid-001"}},
            "payer": {},
            "amount": {"total": 2500, "currency": "CNY"},
        }
    ),
    fail="missing nested payer/amount claim",
)
add(
    "rejects_total_only_inside_skipped_array",
    "A total inside promotion_detail is not amount.total.",
    compact(
        {
            **TOP,
            "payer": PAYER,
            "amount": {"currency": "CNY", "list": [{"total": 2500}]},
        }
    ),
    fail="missing nested payer/amount claim",
)
add(
    "rejects_appid_only_inside_skipped_array",
    "An appid inside a skipped array is not the response appid.",
    compact(
        {k: v for k, v in MIN.items() if k != "appid"} | {"x": [{"appid": "wx123456"}]}
    ),
    fail="missing required payment claim",
)
add(
    "rejects_nine_skipped_levels",
    "Skipped nesting deeper than eight levels fails closed.",
    compact({**MIN, "x": [[[[[[[[[]]]]]]]]]}),
    fail="skipped value nested too deeply",
)
add(
    "rejects_array_closed_by_brace",
    "A skipped array must close with ].",
    compact(MIN)[:-1] + ',"x":[{"a":1}}}',
    fail="mismatched bracket",
)
add(
    "rejects_object_closed_by_bracket",
    "A skipped object must close with }.",
    compact(MIN)[:-1] + ',"x":{"a":1]}',
    fail="mismatched bracket",
)
add(
    "rejects_bound_object_closed_by_bracket",
    "The amount object must close with }.",
    compact({**TOP, "payer": PAYER})[:-1]
    + ',"amount":{"currency":"CNY","total":2500]}',
    fail="mismatched bracket",
)
add(
    "rejects_array_closed_by_brace_after_scalar",
    "A skipped array that ends with a scalar must still close with ].",
    compact(MIN)[:-1] + ',"x":[1,2}',
    fail="mismatched bracket",
)
add(
    "rejects_unclosed_skipped_array",
    "An unclosed skipped array never returns to the response.",
    compact(MIN)[:-1] + ',"x":[1,2',
    fail="incomplete response object",
)
add(
    "rejects_trailing_comma_in_skipped_array",
    "[1,] is not JSON.",
    compact(MIN)[:-1] + ',"x":[1,]}',
    fail="unexpected array end",
)
add(
    "rejects_leading_comma_in_skipped_array",
    "[,1] is not JSON.",
    compact(MIN)[:-1] + ',"x":[,1]}',
    fail="unexpected JSON token",
)
add(
    "rejects_trailing_comma_in_skipped_object",
    '{"a":1,} is not JSON.',
    compact(MIN)[:-1] + ',"x":{"a":1,}}',
    fail="trailing comma",
)
add(
    "rejects_key_in_skipped_array",
    "An array holds values, not members.",
    compact(MIN)[:-1] + ',"x":["a":1]}',
    fail="invalid object separator",
)
add(
    "rejects_escape_inside_skipped_string",
    "Escaped strings stay unsupported inside skipped containers.",
    compact(MIN)[:-1] + ',"x":["a\\"b"]}',
    fail="escaped/control string bytes unsupported",
)
add(
    "rejects_payer_array",
    "Payer must be an object, not an array.",
    compact({**TOP, "payer": [PAYER], "amount": {"total": 2500, "currency": "CNY"}}),
    fail="required claim must have expected type",
)
add(
    "rejects_string_total",
    "A string amount.total is not an integer total.",
    HEAD + '{"total":"2500","currency":"CNY"}}',
    fail="required claim must have expected type",
)
add(
    "rejects_string_payer",
    "payer must be an object, not a string.",
    compact(
        {
            **TOP,
            "payer": "test-openid-001",
            "amount": {"total": 2500, "currency": "CNY"},
        }
    ),
    fail="required claim must have expected type",
)
add(
    "rejects_scalar_payer",
    "payer must be an object, not a scalar.",
    compact({**TOP, "payer": None, "amount": {"total": 2500, "currency": "CNY"}}),
    fail="required claim must have expected type",
)
add(
    "rejects_currency_array",
    "Amount.currency must be a string, not an array.",
    compact({**TOP, "payer": PAYER, "amount": {"total": 2500, "currency": ["CNY"]}}),
    fail="required claim must have expected type",
)
add(
    "rejects_currency_object_after_cny",
    "A duplicate amount.currency object is rejected.",
    compact({**TOP, "payer": PAYER})[:-1]
    + ',"amount":{"total":2500,"currency":"CNY","currency":{}}}',
    fail="required claim must have expected type",
)


def build():
    noir = [
        "//! Generated by scripts/fixtures/generate-wechatpay-scanner-tests.py; do not edit.",
        "//! Regression tests of the claims scanner.",
        "//! The bodies are synthetic and unsigned; see the generator for their source.",
        "use crate::claims::assert_payment_claims;",
        "",
        "// black_box keeps the body and total opaque, so the parser constraints run",
        "// instead of folding at compile time.",
        "fn check<let L: u32>(body: str<L>, expected_total: u64) {",
        f"    let body: BoundedVec<u8, {CAPACITY}> = BoundedVec::from_array(body.as_bytes());",
        "    assert_payment_claims(",
        "        std::hint::black_box(body),",
        f'        BoundedVec::from_array("{TOP["appid"]}".as_bytes()),',
        f'        BoundedVec::from_array("{TOP["mchid"]}".as_bytes()),',
        f'        BoundedVec::from_array("{TOP["transaction_id"]}".as_bytes()),',
        f'        BoundedVec::from_array("{PAYER["openid"]}".as_bytes()),',
        f'        BoundedVec::from_array("{ATT}".as_bytes()),',
        "        std::hint::black_box(expected_total),",
        "    );",
        "}",
        "",
    ]
    names = set()
    variants = [
        "// Positive variants and further rejections of checks that a test above",
        "// already covers.",
        "mod variants {",
        "    use super::check;",
        "",
    ]
    for name, comment, body, total, fail in cases:
        assert name not in names, name
        names.add(name)
        size = len(body.encode())
        assert size <= CAPACITY, (name, size)
        out = noir if name in FAST else variants
        out.append(f"// {comment} ({size} bytes)")
        out.append(
            "#[test]" if fail is None else f'#[test(should_fail_with = "{fail}")]'
        )
        out.append(f"fn {name}() {{")
        out.append(f"    check({lit(body)}, {total});")
        out.append("}")
        out.append("")
    assert FAST <= names, FAST - names
    variants.pop()  # the blank line after the last test
    variants.append("}")
    return "\n".join(noir + variants) + "\n"


if __name__ == "__main__":
    emit(lambda: {NOIR_OUT: build()})
