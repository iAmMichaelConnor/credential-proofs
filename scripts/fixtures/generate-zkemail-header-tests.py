#!/usr/bin/env python3
"""Generate the zkEmail header-parsing regression tests.

The tests pin how get_body_hash selects the bh= tag of a DKIM-Signature field
and how get_email_address pins a bare mailbox.
Body hashes come from Python hashlib and base64; header
indices come from the header text. No case is RSA-signed: get_body_hash and
get_email_address read the header bytes only, so the RSA verification is
independent of which span the prover selects.

Output: noir/zkemail/src/tests/header_parsing.nr
"""

import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generated_noir import ROOT, emit  # noqa: E402

PACKAGE = ROOT / "noir/zkemail"
OUTPUT = PACKAGE / "src/tests/header_parsing.nr"

REAL_BODY = b"REAL BODY\r\n"
FAKE_BODY = b"ATTACKER BODY\r\n"
DEFAULT_CAP = 300

LAST_FIELD = "DKIM-Signature must be the last signed header field"
ONE_BH_TAG = "DKIM-Signature must contain exactly one bh tag"
BH_EQUALS = "The bh tag must be written as 'bh='"
BH_INDEX = "Body hash index does not point at the bh= tag value"
BH_SUFFIX = "No ';' suffix found at asserted bh index"
FIELD_CAP = "Header field exceeds maximum length"
BARE_PREFIX = "Bare mailbox address must be preceded only by whitespace or comments"


def b64(body):
    return base64.b64encode(hashlib.sha256(body).digest()).decode()


REAL = b64(REAL_BODY)
FAKE = b64(FAKE_BODY)
REAL_DIGEST = list(hashlib.sha256(REAL_BODY).digest())
FAKE_DIGEST = list(hashlib.sha256(FAKE_BODY).digest())
assert len(REAL) == len(FAKE) == 44
SIG = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=service.example; s=s1"


def noir_string(text):
    out = []
    for ch in text:
        if ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch in '"\\':
            out.append("\\" + ch)
        else:
            assert 0x20 <= ord(ch) < 0x7F, repr(ch)
            out.append(ch)
    return "".join(out)


def header_expr(text, capacity=None, padding=0):
    """A BoundedVec expression for `text`; `capacity` adds inactive storage."""
    data = text.encode()
    if capacity is None:
        return (
            f"BoundedVec<u8, {len(data)}>",
            f'BoundedVec::from_array(comptime {{ "{noir_string(text)}".as_bytes() }})',
        )
    storage = list(data) + [padding] * (capacity - len(data))
    return (
        f"BoundedVec<u8, {capacity}>",
        f"BoundedVec::from_parts({storage}, {len(data)})",
    )


def test_attribute(fail):
    return "#[test]" if fail is None else f'#[test(should_fail_with = "{fail}")]'


def body_hash_case(
    name,
    comment,
    text,
    field_start,
    bh_index,
    expect,
    fail=None,
    capacity=None,
    padding=0,
    cap=None,
    field_length=None,
):
    """`expect` is the digest the call returns, or None for a rejection."""
    if field_length is None:
        field_length = len(text.encode()) - field_start
    typ, expr = header_expr(text, capacity, padding)
    if cap is None:
        call = "get_body_hash"
    else:
        call = (
            f"get_body_hash_with_field_cap::<{capacity or len(text.encode())}, {cap}>"
        )
    lines = [f"    // {line}" for line in comment]
    lines += [
        f"    {test_attribute(fail)}",
        f"    fn {name}() {{",
        f"        let header: {typ} = {expr};",
        f"        let sequence = Sequence {{ index: {field_start}, length: {field_length} }};",
        f"        let {'body_hash' if expect is not None else '_'} = {call}(header, sequence, {bh_index});",
    ]
    if expect is not None:
        lines.append(f"        assert_eq(body_hash, {expect});")
    lines.append("    }")
    return "\n".join(lines)


def field_text(tags):
    return SIG + tags


def body_hash_cases():
    cases = []
    # Case A: an earlier dkim-signature field is inside the signed header.
    early = f"dkim-signature:v=1; a=rsa-sha256; d=x.example; s=a; bh={FAKE}; b=AAAA"
    last = field_text(f"; h=dkim-signature:from; bh={REAL}; b=")
    text = early + "\r\nfrom:alice@service.example\r\n" + last
    last_start = text.index(last)
    cases.append(
        body_hash_case(
            "earlier_dkim_signature_field_is_rejected",
            [
                "Case A: the prover selects an earlier, attacker-written dkim-signature",
                "field. Only the last field is the signature being verified.",
            ],
            text,
            0,
            text.index(FAKE),
            None,
            LAST_FIELD,
            field_length=len(early),
        )
    )
    cases.append(
        body_hash_case(
            "last_dkim_signature_field_is_accepted",
            ["Case A control: the last field returns the real body hash."],
            text,
            last_start,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    # Case B: a bh= look-alike inside the h= list.
    text = "from:alice@service.example\r\n" + field_text(
        f"; h=from:date:bh={FAKE};x; bh={REAL}; b="
    )
    start = text.index("dkim-signature")
    cases.append(
        body_hash_case(
            "bh_look_alike_in_h_list_is_rejected",
            ["Case B: 'date:bh=' inside the h= value is not a tag start."],
            text,
            start,
            text.index(FAKE),
            None,
            BH_INDEX,
        )
    )
    cases.append(
        body_hash_case(
            "real_bh_after_h_list_look_alike_is_accepted",
            ["Case B control: the real bh= tag returns the real body hash."],
            text,
            start,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    # Case C1: a copied 'Date:bh=' header inside z=.
    text = field_text(f"; z=From:a@b.c|Date:bh={FAKE};|To:x@y.z; bh={REAL}; b=")
    cases.append(
        body_hash_case(
            "bh_look_alike_in_z_copied_headers_is_rejected",
            ["Case C1: 'Date:bh=' inside a z= value is not a tag start."],
            text,
            0,
            text.index(FAKE),
            None,
            BH_INDEX,
        )
    )
    # Case D: mixed prefix 'e bh=' inside an i= value.
    text = field_text(f"; i=xe bh={FAKE};; bh={REAL}; b=")
    cases.append(
        body_hash_case(
            "bh_look_alike_in_i_value_is_rejected",
            [
                "Case D: 'e bh=' inside an i= value is not a tag start."
            ],
            text,
            0,
            text.index(FAKE),
            None,
            BH_INDEX,
        )
    )
    # Duplicate bh tags (RFC 6376 section 3.2: tags must not be duplicated).
    text = field_text(f"; bh={FAKE}; bh={REAL}; b=")
    for which, digest_text in (("first", FAKE), ("second", REAL)):
        cases.append(
            body_hash_case(
                f"duplicate_bh_tags_reject_the_{which}",
                ["A field with two bh tags is invalid; neither value is accepted."],
                text,
                0,
                text.index(digest_text),
                None,
                ONE_BH_TAG,
            )
        )
    text = field_text(f"; z=Subject:x;bh={FAKE}; bh={REAL}; b=")
    cases.append(
        body_hash_case(
            "unencoded_semicolon_in_z_value_is_rejected",
            [
                "A signer that copies ';' into z= unencoded creates a second bh tag start;",
                "the field is rejected instead of selecting either value.",
            ],
            text,
            0,
            text.index(REAL),
            None,
            ONE_BH_TAG,
        )
    )
    text = field_text(f"; bh ={FAKE}; bh={REAL}; b=")
    cases.append(
        body_hash_case(
            "bh_tag_with_space_before_equals_counts_as_a_bh_tag",
            ["'bh =' is a bh tag (FWS before '='), so a second bh= is a duplicate."],
            text,
            0,
            text.index(REAL),
            None,
            ONE_BH_TAG,
        )
    )
    text = field_text(f"; bh ={REAL}; b=")
    cases.append(
        body_hash_case(
            "sole_bh_tag_with_space_before_equals_is_unsupported",
            ["The supported profile writes the tag as 'bh='."],
            text,
            0,
            text.index(REAL),
            None,
            BH_EQUALS,
        )
    )
    text = field_text("; b=")
    cases.append(
        body_hash_case(
            "field_without_bh_tag_is_rejected",
            ["A field without a bh tag has no body hash."],
            text,
            0,
            len(SIG) + 4,
            None,
            ONE_BH_TAG,
        )
    )
    # Accepted tag-start forms.
    for name, tags in (
        ("first_tag_without_space", f"bh={REAL}; v=1; d=service.example; b="),
        ("first_tag_after_space", f" bh={REAL}; v=1; d=service.example; b="),
    ):
        text = "dkim-signature:" + tags
        cases.append(
            body_hash_case(
                f"bh_{name}_is_accepted",
                ["bh= as the first tag of the field."],
                text,
                0,
                text.index(REAL),
                REAL_DIGEST,
            )
        )
    text = field_text(f";bh={REAL}; b=")
    cases.append(
        body_hash_case(
            "bh_after_semicolon_without_space_is_accepted",
            ["';bh=' is a tag start (FWS is optional in RFC 6376 tag-list)."],
            text,
            0,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    text = field_text(f";\tbh={REAL}; b=")
    cases.append(
        body_hash_case(
            "bh_after_semicolon_and_tab_is_accepted",
            ["';<TAB>bh=' is a tag start."],
            text,
            0,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    text = field_text(f"; bh={REAL}; b=")
    for name, delta in (("before", -1), ("after", 1)):
        cases.append(
            body_hash_case(
                f"bh_index_one_{name}_the_value_is_rejected",
                ["The index must be the first byte after 'bh='."],
                text,
                0,
                text.index(REAL) + delta,
                None,
                BH_INDEX,
            )
        )
    # Bh= is the last tag, so its value ends at the end of the field.
    text = field_text(f"; h=to; b=; bh={REAL}")
    for name, padding in (("zero", 0), ("nonzero", ord("X"))):
        cases.append(
            body_hash_case(
                f"bh_last_tag_with_{name}_padding_is_accepted",
                [
                    "The value ends at the field end; inactive storage is not read."
                ],
                text,
                0,
                text.index(REAL),
                REAL_DIGEST,
                capacity=len(text) + 32,
                padding=padding,
            )
        )
    cases.append(
        body_hash_case(
            "bh_last_tag_at_header_capacity_is_accepted",
            ["Header length equals capacity; no read beyond the storage."],
            text,
            0,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    text = field_text(f"; bh={REAL}X; b=")
    cases.append(
        body_hash_case(
            "bh_value_longer_than_44_bytes_is_rejected",
            ["The 44-byte value must be followed by ';' or the end of the field."],
            text,
            0,
            text.index(REAL),
            None,
            BH_SUFFIX,
        )
    )

    # Field cap.
    def sized_field(size):
        base = field_text(f"; h=from:to; bh={REAL}; b=")
        filler = size - len(base) - len("; z=")
        assert filler > 0
        return field_text(f"; z={'a' * filler}; h=from:to; bh={REAL}; b=")

    text = sized_field(DEFAULT_CAP)
    assert len(text) == DEFAULT_CAP
    cases.append(
        body_hash_case(
            "field_at_default_cap_is_accepted",
            [f"A {DEFAULT_CAP}-byte field fits the default cap."],
            text,
            0,
            text.index(REAL),
            REAL_DIGEST,
        )
    )
    text = sized_field(DEFAULT_CAP + 1)
    cases.append(
        body_hash_case(
            "field_over_default_cap_is_rejected",
            ["Get_body_hash keeps the default cap and its length assertion."],
            text,
            0,
            text.index(REAL),
            None,
            FIELD_CAP,
        )
    )
    for size, cap, expect, fail in (
        (330, 400, REAL_DIGEST, None),
        (400, 400, REAL_DIGEST, None),
        (401, 400, None, FIELD_CAP),
    ):
        text = sized_field(size)
        verdict = "accepted" if fail is None else "rejected"
        cases.append(
            body_hash_case(
                f"field_of_{size}_bytes_with_cap_{cap}_is_{verdict}",
                [f"Get_body_hash_with_field_cap with cap {cap}."],
                text,
                0,
                text.index(REAL),
                expect,
                fail,
                capacity=512,
                cap=cap,
            )
        )
    return cases


def address_case(name, comment, value, address, fail=None, expect=True):
    text = "\r\nfrom:" + value + "\r\n"
    data = text.encode()
    field_length = len(data) - 4
    index = text.rindex(address)
    typ, expr = header_expr(text)
    lines = [f"    // {line}" for line in comment]
    lines += [
        f"    {test_attribute(fail)}",
        f"    fn {name}() {{",
        f"        let header: {typ} = {expr};",
        f"        let {'address' if fail is None else '_'} = get_email_address(",
        "            header,",
        f"            Sequence {{ index: 2, length: {field_length} }},",
        f"            Sequence {{ index: {index}, length: {len(address)} }},",
        '            comptime { "from".as_bytes() },',
        "        );",
    ]
    if fail is None:
        lines.append(
            f'        assert_eq(address, BoundedVec::from_array(comptime {{ "{address}".as_bytes() }}));'
        )
    lines.append("    }")
    return "\n".join(lines)


def address_cases():
    cases = []
    victim = "alice@example.com"
    rejected = [
        ("obs_local_part_with_spaces", "bob . alice@example.com"),
        ("obs_local_part_with_trailing_space", "bob. alice@example.com"),
        ("obs_local_part_with_comment", "bob.(c) alice@example.com"),
        ("obs_local_part_with_quoted_word", '"bob". alice@example.com'),
        ("obs_local_part_with_comment_before_dot", "bob (c) . alice@example.com"),
        ("obs_local_part_after_comment", "(c) . alice@example.com"),
        ("address_list", "bob, alice@example.com"),
        ("unquoted_display_name_without_brackets", "Bob Smith alice@example.com"),
    ]
    for name, value in rejected:
        cases.append(
            address_case(
                f"bare_{name}_is_rejected",
                [
                    f"'{value}' does not name {victim}; the span is a strict suffix."
                ],
                value,
                victim,
                BARE_PREFIX,
            )
        )
    accepted = [
        ("spaces", "  alice@example.com  "),
        ("tab_and_comment", "\t(note: bob.alice@example.com) alice@example.com (c)"),
        ("angle_form_display_name", "Bob Smith <alice@example.com>"),
    ]
    for name, value in accepted:
        cases.append(
            address_case(
                f"bare_{name}_is_accepted"
                if "angle" not in name
                else f"{name}_is_accepted",
                ["CFWS around the mailbox stays accepted."],
                value,
                victim,
            )
        )
    return cases


def complete_field_cases():
    cases = []
    for name, text, length, fail in [
        ("unfolded_subject", "Subject: approve\r\nDate: today", 16, None),
        ("terminal_subject", "Subject: approve", 16, None),
        (
            "subject_wrong_end_hint",
            "Subject: approve\r\nDate: today",
            15,
            "Header field must end with CRLF",
        ),
        (
            "subject_space_continuation",
            "Subject: approve\r\n cancel",
            16,
            "Header field continues on a folded line",
        ),
        (
            "subject_tab_continuation",
            "Subject: approve\r\n\tcancel",
            16,
            "Header field continues on a folded line",
        ),
        (
            "full_folded_subject",
            "Subject: approve\r\n cancel",
            25,
            "Header field must not contain newlines",
        ),
    ]:
        typ, expr = header_expr(text)
        cases.append(
            f'{test_attribute(fail)}\nfn {name}() {{\nlet header: {typ} = {expr};\nconstrain_header_field::<{len(text.encode())}, 64, 7>(header, Sequence {{index:0,length:{length}}}, comptime {{"Subject".as_bytes()}});\n}}'
        )
    return cases


def build():
    parts = [
        "// Generated by scripts/fixtures/generate-zkemail-header-tests.py from",
        "// Python hashlib and base64. Do not edit by hand.",
        "",
        "mod complete_field {",
        "use crate::{headers::constrain_header_field, Sequence};",
        "\n\n".join(complete_field_cases()),
        "}",
        "",
        "mod body_hash {",
        "    use crate::{headers::body_hash::{get_body_hash, get_body_hash_with_field_cap}, Sequence};",
        "",
        "\n\n".join(body_hash_cases()),
        "}",
        "",
        "mod email_address {",
        "    use crate::{headers::email_address::get_email_address, Sequence};",
        "",
        "\n\n".join(address_cases()),
        "}",
        "",
    ]
    return "\n".join(parts)


if __name__ == "__main__":
    emit(lambda: {OUTPUT: build()})
