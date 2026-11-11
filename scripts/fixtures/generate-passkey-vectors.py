#!/usr/bin/env python3
"""Generate the passkey (WebAuthn) browser-form test vectors.

One deterministic P-256 test key signs synthetic but correctly formatted
authenticatorData and clientDataJSON for each case. The clientDataJSON byte
layouts follow what current browsers emit for navigator.credentials.get():

- Chrome, Edge and Android Chrome (Chromium client_data_json.cc): type,
  challenge, origin, "crossOrigin":false; about one ceremony in five adds an
  "other_keys_can_be_added_here" member after crossOrigin.
- Safari, iOS and iPadOS (WebKit WebAuthenticationUtils.cpp): type,
  challenge, origin; crossOrigin is omitted for a same-origin ceremony.
- Firefox 137 and later: type, challenge, origin, "crossOrigin":false.

The key is a public test scalar; nothing here comes from a real authenticator.
Outputs:
- noir/passkey_auth/src/browser_vectors.nr
- fixtures/data/passkey-browser-forms.synthetic.json
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generated_noir import ROOT, emit  # noqa: E402

PACKAGE = ROOT / "noir/passkey_auth"
NOIR_OUT = PACKAGE / "src/browser_vectors.nr"
JSON_OUT = (
    ROOT / "fixtures/data/passkey-browser-forms.synthetic.json"
)

# P-256 domain parameters (SEC 2, secp256r1).
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return x, (lam * (p1[0] - x) - p1[1]) % P


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def sign(secret, message, high_s=False):
    """ECDSA-SHA256 with a nonce derived from the key and message (test only)."""
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    k = (
        int.from_bytes(
            hashlib.sha256(b"nonce" + secret.to_bytes(32, "big") + digest).digest(),
            "big",
        )
        % N
    )
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * secret) % N
    assert r and s
    low = min(s, N - s)
    return r, (N - low if high_s else low)


def der(r, s):
    def integer(v):
        b = v.to_bytes(32, "big").lstrip(b"\0")
        if b[0] & 0x80:
            b = b"\0" + b
        return bytes([2, len(b)]) + b

    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


SECRET = (
    int.from_bytes(
        hashlib.sha256(b"credential-proofs passkey browser-form test key").digest(), "big"
    )
    % N
)
PUBLIC = mul(SECRET, G)
RP_ID = "app.example"
ORIGIN = "https://app.example"
CHALLENGE = 0x00A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F
OTHER_CHALLENGE = CHALLENGE + 1
CLIENT_MAX, RP_MAX, ORIGIN_MAX = 256, 64, 128
GREASE = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"'


def prefix(challenge=CHALLENGE, origin=ORIGIN):
    encoded = b64url(challenge.to_bytes(32, "big"))
    return '{"type":"webauthn.get","challenge":"%s","origin":"%s"' % (encoded, origin)


def auth_data(flags, counter):
    return (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + counter.to_bytes(4, "big")
    )


LONG_ORIGIN = (
    "https://" + "x" * 60 + ".app.example"
)  # 80 bytes: the extra-member form cannot fit
XO = "clientDataJSON crossOrigin must be false or omitted"
FORM = "clientDataJSON has an unsupported length or extra member"
END = "clientDataJSON must end with }"


def same_length_member(text):
    """Pad `text` with one more member so it is as long as the GREASE member."""
    pad = 109 - len(text) - len(',"pad":""')
    assert pad >= 0
    out = text + ',"pad":"' + "a" * pad + '"'
    assert len(out) == len(GREASE)
    return out


# (name, description, clientDataJSON, flags, counter, expected failure or None, origin)
# A failure string is the circuit assert message; "" means a failure without
# a message (inside the flag checks).
CASES = [
    (
        "chrome",
        "Chrome desktop, same origin",
        prefix() + ',"crossOrigin":false}',
        0x05,
        0,
        None,
    ),
    (
        "chrome_grease",
        "Chrome with the GREASE member",
        prefix() + ',"crossOrigin":false' + GREASE + "}",
        0x05,
        0,
        None,
    ),
    (
        "android_chrome",
        "Android Chrome with Google Password Manager (synced, BE|BS)",
        prefix() + ',"crossOrigin":false}',
        0x1D,
        0,
        None,
    ),
    (
        "safari",
        "Safari, iOS and iPadOS, same origin (crossOrigin omitted)",
        prefix() + "}",
        0x1D,
        0,
        None,
    ),
    (
        "firefox",
        "Firefox 137+ with a security key (signature counter)",
        prefix() + ',"crossOrigin":false}',
        0x05,
        42,
        None,
    ),
    (
        "chrome_long_origin",
        "Chrome with an 80-byte origin",
        prefix(origin=LONG_ORIGIN) + ',"crossOrigin":false}',
        0x05,
        0,
        None,
        LONG_ORIGIN,
    ),
    (
        "safari_long_origin",
        "Safari with an 80-byte origin",
        prefix(origin=LONG_ORIGIN) + "}",
        0x1D,
        0,
        None,
        LONG_ORIGIN,
    ),
    (
        "cross_origin_true",
        "Chrome inside a cross-site iframe",
        prefix() + ',"crossOrigin":true,"topOrigin":"https://evil.example"}',
        0x05,
        0,
        XO,
    ),
    (
        "cross_origin_true_only",
        "crossOrigin true without topOrigin",
        prefix() + ',"crossOrigin":true}',
        0x05,
        0,
        XO,
    ),
    (
        "safari_cross_origin",
        "Safari inside a cross-site iframe",
        prefix() + ',"crossOrigin":true,"topOrigin":"https://evil.example"}',
        0x1D,
        0,
        XO,
    ),
    (
        "top_origin_after_false",
        "topOrigin after crossOrigin false",
        prefix() + ',"crossOrigin":false,"topOrigin":"https://evil.example"}',
        0x05,
        0,
        FORM,
    ),
    (
        "top_origin_without_cross_origin",
        "topOrigin with crossOrigin omitted",
        prefix() + ',"topOrigin":"https://evil.example"}',
        0x1D,
        0,
        XO,
    ),
    (
        "members_without_cross_origin",
        "GREASE member with crossOrigin omitted",
        prefix() + GREASE + "}",
        0x1D,
        0,
        XO,
    ),
    (
        "wrong_origin",
        "origin of another site",
        prefix(origin="https://evil.example") + ',"crossOrigin":false}',
        0x05,
        0,
        "clientDataJSON origin mismatch",
    ),
    (
        "wrong_challenge",
        "challenge for another action",
        prefix(challenge=OTHER_CHALLENGE) + ',"crossOrigin":false}',
        0x05,
        0,
        "clientDataJSON challenge mismatch",
    ),
    (
        "second_challenge",
        "second challenge member after the prefix",
        prefix()
        + ',"crossOrigin":false,"challenge":"%s"}'
        % b64url(OTHER_CHALLENGE.to_bytes(32, "big")),
        0x05,
        0,
        FORM,
    ),
    (
        "second_origin",
        "second origin member after the prefix",
        prefix() + ',"crossOrigin":false,"origin":"https://evil.example"}',
        0x05,
        0,
        FORM,
    ),
    (
        "second_type",
        "second type member after the prefix",
        prefix() + ',"crossOrigin":false,"type":"webauthn.create"}',
        0x05,
        0,
        FORM,
    ),
    (
        "second_cross_origin",
        "second crossOrigin member after the prefix",
        prefix() + ',"crossOrigin":false,"crossOrigin":true}',
        0x05,
        0,
        FORM,
    ),
    (
        "escaped_challenge_key",
        "escaped spelling of challenge after the prefix",
        prefix() + ',"crossOrigin":false,"chall\\u0065nge":"x"}',
        0x05,
        0,
        FORM,
    ),
    (
        "case_folded_keys",
        "keys that Go encoding/json folds onto challenge, origin and crossOrigin, at the GREASE length",
        prefix()
        + ',"crossOrigin":false'
        + same_length_member(
            ',"Challenge":"EVIL","ORIGIN":"https://evil.example","CrossOrigin":true'
        )
        + "}",
        0x05,
        0,
        FORM,
    ),
    (
        "second_challenge_grease_length",
        "second challenge member at the GREASE length",
        prefix()
        + ',"crossOrigin":false'
        + same_length_member(
            ',"challenge":"%s"' % b64url(OTHER_CHALLENGE.to_bytes(32, "big"))
        )
        + "}",
        0x05,
        0,
        FORM,
    ),
    (
        "truncated",
        "Chrome form without the closing brace",
        prefix() + ',"crossOrigin":false',
        0x05,
        0,
        FORM,
    ),
    (
        "truncated_grease",
        "GREASE form cut inside the extra member",
        (prefix() + ',"crossOrigin":false' + GREASE)[:-20],
        0x05,
        0,
        FORM,
    ),
    (
        "truncated_origin",
        "JSON cut inside the origin member",
        prefix()[:-1],
        0x05,
        0,
        "clientDataJSON origin mismatch",
    ),
    (
        "trailing_comma",
        "crossOrigin false followed by a bare comma",
        prefix() + ',"crossOrigin":false,}',
        0x05,
        0,
        FORM,
    ),
    (
        "grease_without_brace",
        "GREASE form with a different last byte",
        prefix() + ',"crossOrigin":false' + GREASE + " ",
        0x05,
        0,
        END,
    ),
    (
        "uv_missing",
        "user verification required but not performed",
        prefix() + ',"crossOrigin":false}',
        0x01,
        0,
        "authenticator did not verify the user",
    ),
]


def noir_bytes(data, size):
    assert len(data) <= size
    values = list(data) + [0] * (size - len(data))
    return "[" + ", ".join(str(v) for v in values) + "]"


def build():
    x, y = (v.to_bytes(32, "big") for v in PUBLIC)
    noir = [
        "//! Browser-form WebAuthn test vectors. Generated by",
        "//! scripts/fixtures/generate-passkey-vectors.py; do not edit.",
        "//! A deterministic public test key signs synthetic authenticatorData and",
        "//! clientDataJSON in the layouts that current browsers emit.",
        "use crate::webauthn::{assert_valid_webauthn, PasskeyPublicKey, WebAuthnAssertion, WebAuthnPolicy};",
        "",
        "fn key() -> PasskeyPublicKey {",
        f"    PasskeyPublicKey {{ x: {noir_bytes(x, 32)}, y: {noir_bytes(y, 32)} }}",
        "}",
        "",
        f"fn policy(origin: [u8; {ORIGIN_MAX}], origin_len: u32) -> WebAuthnPolicy<{RP_MAX}, {ORIGIN_MAX}> {{",
        "    WebAuthnPolicy {",
        f"        rp_id: {noir_bytes(RP_ID.encode(), RP_MAX)},",
        f"        rp_id_len: {len(RP_ID)},",
        "        origin,",
        "        origin_len,",
        "        require_user_verification: true,",
        "    }",
        "}",
        "",
        f"fn check(origin: [u8; {ORIGIN_MAX}], origin_len: u32, assertion: WebAuthnAssertion<{CLIENT_MAX}>) {{",
        f"    let policy = policy(origin, origin_len);",
        f"    assert_valid_webauthn::<{CLIENT_MAX}, {RP_MAX}, {ORIGIN_MAX}>(key(), 0x{CHALLENGE:064x}, policy, assertion);",
        "}",
    ]
    cases = []
    for name, description, client, flags, counter, failure, *rest in CASES:
        origin = rest[0] if rest else ORIGIN
        client_bytes = client.encode()
        authenticator = auth_data(flags, counter)
        message = authenticator + hashlib.sha256(client_bytes).digest()
        r, s = sign(SECRET, message)
        attribute = (
            "#[test]"
            if failure is None
            else (
                "#[test(should_fail)]"
                if failure == ""
                else f'#[test(should_fail_with = "{failure}")]'
            )
        )
        noir += [
            "",
            f"// {description}.",
            f"// {client}",
            attribute,
            f"fn {name}() {{",
            "    check(",
            f"        {noir_bytes(origin.encode(), ORIGIN_MAX)},",
            f"        {len(origin)},",
            "        WebAuthnAssertion {",
            f"        authenticator_data: {noir_bytes(authenticator, 37)},",
            f"        client_data_json: {noir_bytes(client_bytes, CLIENT_MAX)},",
            f"        client_data_json_len: {len(client_bytes)},",
            f"        signature: {noir_bytes(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'), 64)},",
            "        },",
            "    );",
            "}",
        ]
        # The SDK receives the browser's DER signature; give the accepted
        # Safari case a high s so the importer's low-s normalisation is used.
        der_sig = der(*sign(SECRET, message, high_s=(name == "safari")))
        cases.append(
            {
                "name": name,
                "description": description,
                "accepted": failure is None,
                **({"origin": origin} if origin != ORIGIN else {}),
                "response": {
                    "authenticatorData": b64url(authenticator),
                    "clientDataJSON": b64url(client_bytes),
                    "signature": b64url(der_sig),
                },
            }
        )
    fixture = {
        "note": "Synthetic. Generated by scripts/fixtures/generate-passkey-vectors.py from a public test key; not a real authenticator.",
        "policy": {
            "challenge": str(CHALLENGE),
            "rpId": RP_ID,
            "origin": ORIGIN,
            "publicKeySec1": "04" + x.hex() + y.hex(),
            "requireUserVerification": True,
        },
        "cases": cases,
    }
    return "\n".join(noir) + "\n", json.dumps(fixture, indent=2) + "\n"


def outputs():
    noir, fixture = build()
    return {NOIR_OUT: noir, JSON_OUT: fixture}


if __name__ == "__main__":
    emit(outputs)
