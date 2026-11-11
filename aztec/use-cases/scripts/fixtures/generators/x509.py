#!/usr/bin/env python3
"""Writes src/fixture.nr and fixtures/manifest.json of the certified-key card
account account-authorisation/jpki and login link login-link/jpki.

python3 scripts/fixtures/generators/x509.py --instance account-authorisation/jpki \
    --account <field hex> --action <field hex> --next-action <field hex>
python3 scripts/fixtures/generators/x509.py --instance login-link/jpki \
    --account <field hex> --message <field hex>

A local synthetic chain (root, holder, OCSP responder) and
OCSP responses at 1900000000, built with the repository's helpers in
scripts/fixtures/lib. It is not a JPKI chain. The
RSA keys are derived deterministically from public seeds, so anyone can
regenerate them and sign with them; no key is stored. The holder signs the
card challenge over (account, action, session) three times: the action with
session 3..3, the next action (tx nonce + 1) with the same session, and the
next action with session 5..5. For a login link, the holder signs the card
challenge over (account, message, session 3..3) once, where the message is
`uc_login_link::timed_challenge(challenge, NOW - 60)` that the instance test
observes. Needs Python `cryptography`. No network.
"""

import argparse
import datetime
import hashlib
import json
import random
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
ROOT = PROJECT.parents[1]
sys.path.insert(0, str(ROOT / "scripts/fixtures"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier  # noqa: E402
from lib.x509_fixture import signed_ocsp  # noqa: E402
from nr_format import format_noir  # noqa: E402

NOW = 1900000000
SESSION = bytes([3]) * 32
NEXT_SESSION = bytes([5]) * 32
SMALL_PRIMES = [
    p for p in range(3, 2000) if all(p % q for q in range(2, int(p**0.5) + 1))
]


def probable_prime(n, rng):
    if any(n % p == 0 for p in SMALL_PRIMES):
        return n in SMALL_PRIMES
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(40):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def seeded_key(label, bits):
    """An RSA key derived from a public seed (test only; not secret)."""
    rng = random.Random(
        hashlib.sha256(f"credential-proofs synthetic {label}".encode()).digest()
    )

    def prime():
        while True:
            c = rng.getrandbits(bits // 2) | (3 << (bits // 2 - 2)) | 1
            if (c - 1) % 65537 and probable_prime(c, rng):
                return c

    p, q = prime(), prime()
    while q == p:
        q = prime()
    n, e = p * q, 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    numbers = rsa.RSAPrivateNumbers(
        p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), rsa.RSAPublicNumbers(e, n)
    )
    key = numbers.private_key()
    assert key.key_size == bits
    return key


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def jpki(account, actions):
    """The chain of scripts/fixtures/generate-x509-fixtures.py (jpki)."""
    keys = {
        n: seeded_key(f"jpki account {n} key v1", 2048)
        for n in ("root", "holder", "responder")
    }
    utc = datetime.timezone.utc
    before, after = (
        datetime.datetime(2025, 1, 1, tzinfo=utc),
        datetime.datetime(2033, 1, 1, tzinfo=utc),
    )

    def name(s):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, "SYNTHETIC TEST AUTHORITY"
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, s),
            ]
        )

    ca_name = name("Not JPKI - Local Test Root")

    def cert(key, subject, serial, role):
        b = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(before)
            .not_valid_after(after)
        )
        b = b.add_extension(
            x509.BasicConstraints(ca=role == 0, path_length=None), True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=role != 0,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=role == 0,
                crl_sign=role == 0,
                encipher_only=None,
                decipher_only=None,
            ),
            True,
        )
        if role == 1:
            b = b.add_extension(
                x509.CertificatePolicies(
                    [
                        x509.PolicyInformation(
                            ObjectIdentifier("1.2.392.200149.8.5.1.3.30"), None
                        )
                    ]
                ),
                False,
            )
        if role == 2:
            b = b.add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False
            ).add_extension(x509.OCSPNoCheck(), False)
        return b.sign(keys["root"], hashes.SHA256())

    root = cert(keys["root"], ca_name, 1, 0)
    leaf = cert(keys["holder"], name("Synthetic holder no personal identity"), 2, 1)
    responder = cert(
        keys["responder"], name("Synthetic delegated OCSP responder"), 3, 2
    )
    now = datetime.datetime.fromtimestamp(NOW, utc)
    ocsp = signed_ocsp(root, leaf, responder, keys["responder"], now, True, 600, -60)

    def redc(k):
        n = k.public_key().public_numbers().n
        r = (1 << (4096 + 6)) // n
        return [(r >> (120 * i)) & ((1 << 120) - 1) for i in range(18)]

    spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policy = {
        "anchor_class": 1,
        "root_sha256": list(hashlib.sha256(der(root)).digest()),
        "holder_spki_sha256": list(hashlib.sha256(spki).digest()),
        "max_ocsp_age": 300,
    }
    sign = lambda action, session: keys["holder"].sign(  # noqa: E731
        b"MIKE_JPKI_CARD_AUTH_V1__________" + account + action + session,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    fields = {}
    for k, data, cap in [
        ("root", der(root), 2048),
        ("certificate", der(leaf), 2048),
        ("responder", der(responder), 2048),
        ("ocsp", ocsp, 4096),
    ]:
        assert len(data) <= cap
        fields[k] = list(data) + [0] * (cap - len(data))
        fields[k + "_len"] = len(data)
    fields["holder_signature"] = list(sign(actions[0], SESSION))
    fields["root_redc"] = redc(keys["root"])
    fields["holder_redc"] = redc(keys["holder"])
    fields["responder_redc"] = redc(keys["responder"])
    fields["session"] = list(SESSION)
    return (
        policy,
        fields,
        sign,
        {
            "root_sha256": bytes(policy["root_sha256"]).hex(),
            "holder_spki_sha256": bytes(policy["holder_spki_sha256"]).hex(),
        },
    )


def literal(value, indent):
    if isinstance(value, dict):
        return f"BoundedVec::from_parts({literal(value['storage'], indent)}, {value['len']})"
    if isinstance(value, list):
        items = [literal(v, indent) for v in value]
        lines = [", ".join(items[i : i + 16]) for i in range(0, len(items), 16)]
        if len(lines) <= 1:
            return "[" + "".join(lines) + "]"
        inner = f",\n{indent}    ".join(lines)
        return f"[\n{indent}    {inner},\n{indent}]"
    if isinstance(value, bytes):
        return literal(list(value), indent)
    return str(value)


def field(hexstr):
    value = hexstr.lower().removeprefix("0x").rjust(64, "0")
    assert len(value) == 64 and int(value, 16) < 2**254
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--instance", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--action")
    parser.add_argument("--next-action")
    parser.add_argument("--message")
    args = parser.parse_args()
    use_case, scheme = args.instance.split("/")
    if scheme != "jpki" or use_case not in ("account-authorisation", "login-link"):
        parser.error("the instance must be account-authorisation/jpki or login-link/jpki")
    if use_case == "login-link":
        if args.message is None or args.action or args.next_action:
            parser.error("a login link takes --account and --message")
        return login_link(args, scheme)
    if args.action is None or args.next_action is None or args.message:
        parser.error("an account takes --account, --action and --next-action")
    contract = "JpkiAccount"
    manifest = json.loads((PROJECT / "use-cases.json").read_text())
    assert any(
        i["use_case"] == use_case and i["scheme"] == scheme
        for i in manifest["instances"]
    )
    account, action, next_action = (
        field(v) for v in (args.account, args.action, args.next_action)
    )
    a, b, c = (bytes.fromhex(v) for v in (account, action, next_action))
    policy, fields, sign, claims = jpki(a, [b, c])
    indent = " " * 12
    policy_text = "\n".join(
        f"{indent}{k}: {literal(v, indent)}," for k, v in policy.items()
    )
    indent = " " * 8
    field_text = "\n".join(
        f"{indent}{k}: {literal(v, indent)}," for k, v in fields.items()
    )
    fixture = f"""//! Generated by scripts/fixtures/generators/x509.py; see fixtures/manifest.json. Do not edit.
//! A local synthetic certificate chain and OCSP responses under RSA keys
//! derived from public seeds. It is not a JPKI chain; anyone can sign with the keys.
use crate::{contract}::{{AuthInput, AuthPolicy}};

/// The account address and actions that the card challenges name.
pub global ACCOUNT: Field = 0x{account};
pub global ACTION: Field = 0x{action};
pub global NEXT_ACTION: Field = 0x{next_action};
/// The anchor time that the OCSP responses are fresh at (produced at NOW,
/// this update NOW - 60, next update NOW + 600, max age 300).
pub global NOW: u64 = {NOW};

/// The holder's signature over the next action with the same session.
pub global NEXT_SAME_SESSION_SIGNATURE: [u8; 256] = {literal(sign(c, SESSION), "")};
/// Another session, and the holder's signature over the next action with it.
pub global NEXT_SESSION: [u8; 32] = {literal(NEXT_SESSION, "")};
pub global NEXT_SESSION_SIGNATURE: [u8; 256] = {literal(sign(c, NEXT_SESSION), "")};

pub fn auth() -> AuthInput {{
    AuthInput {{
        policy: AuthPolicy {{
{policy_text}
        }},
{field_text}
    }}
}}
"""
    directory = PROJECT / args.instance
    (directory / "fixtures").mkdir(exist_ok=True)
    fixture = format_noir(fixture)
    (directory / "src/fixture.nr").write_text(fixture)
    path = directory / "fixtures/manifest.json"
    inputs = {}
    for rel in [
        "scripts/fixtures/lib/x509_fixture.py",
        "aztec/use-cases/scripts/fixtures/generators/x509.py",
    ]:
        inputs[rel] = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
    record = {
        "schema": "uc-fixture-v1",
        "scheme": scheme,
        "use_case": use_case,
        "kind": "synthetic",
        "generator": {
            "argv": [
                "python3",
                "scripts/fixtures/generators/x509.py",
                "--instance",
                args.instance,
                "--account",
                account,
                "--action",
                action,
                "--next-action",
                next_action,
            ],
            "cwd": "aztec/use-cases",
            "library": "scripts/fixtures/lib (x509_fixture.signed_ocsp)",
        },
        "inputs": inputs,
        "key_provenance": f"RSA keys derived from the public seeds 'credential-proofs synthetic {scheme} account <role> key v1'; a local test chain, not JPKI. Anyone can sign with them.",
        "claims": {
            **claims,
            "now": NOW,
            "session": SESSION.hex(),
            "next_session": NEXT_SESSION.hex(),
        },
        "notes": [
            "The account and actions are the shell address and action hashes observed in TXE; the test fixture_is_for_this_account fails with the values to use when they change.",
            "Negative cases mutate this fixture in src/test.nr.",
        ],
        "outputs": {"src/fixture.nr": hashlib.sha256(fixture.encode()).hexdigest()},
    }
    path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"Wrote {args.instance}/src/fixture.nr for account {account} action {action}")


def login_link(args, scheme):
    """The fixture of login-link/jpki: one card signature over the
    timed link challenge, and the chain and OCSP responses as BoundedVecs."""
    manifest = json.loads((PROJECT / "use-cases.json").read_text())
    assert any(
        i["use_case"] == "login-link" and i["scheme"] == scheme
        for i in manifest["instances"]
    )
    account, message = field(args.account), field(args.message)
    a, m = bytes.fromhex(account), bytes.fromhex(message)
    policy, fields, sign, claims = jpki(a, [m, m])
    for name in ("root", "certificate", "responder", "ocsp"):
        fields[name] = {
            "storage": fields[name],
            "len": fields.pop(name + "_len"),
        }
    issued_at = NOW - 60
    login = {**policy, **fields, "issued_at": issued_at}
    struct = "JpkiLogin"
    indent = " " * 8
    body = "\n".join(f"{indent}{k}: {literal(v, indent)}," for k, v in login.items())
    authority = "JPKI"
    fixture = f"""//! Generated by scripts/fixtures/generators/x509.py; see fixtures/manifest.json. Do not edit.
//! A local synthetic certificate chain and OCSP responses under RSA keys
//! derived from public seeds. It is not a {authority} chain; anyone can sign with the keys.
use uc_adapter_{scheme}::{struct};

/// The contract address (the TXE shell) and the timed link challenge that
/// the card signature names.
pub global ACCOUNT: Field = 0x{account};
pub global MESSAGE: Field = 0x{message};
/// The anchor time that the OCSP responses are fresh at (produced at NOW,
/// this update NOW - 60, next update NOW + 600, max age 300), and the issue
/// time that the holder signs.
pub global NOW: u64 = {NOW};
pub global ISSUED_AT: u64 = {issued_at};

pub fn login() -> {struct} {{
    {struct} {{
{body}
    }}
}}
"""
    directory = PROJECT / args.instance
    (directory / "fixtures").mkdir(exist_ok=True)
    fixture = format_noir(fixture)
    (directory / "src/fixture.nr").write_text(fixture)
    path = directory / "fixtures/manifest.json"
    inputs = {}
    for rel in [
        "scripts/fixtures/lib/x509_fixture.py",
        "aztec/use-cases/scripts/fixtures/generators/x509.py",
    ]:
        inputs[rel] = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
    record = {
        "schema": "uc-fixture-v1",
        "scheme": scheme,
        "use_case": "login-link",
        "kind": "synthetic",
        "generator": {
            "argv": [
                "python3",
                "scripts/fixtures/generators/x509.py",
                "--instance",
                args.instance,
                "--account",
                account,
                "--message",
                message,
            ],
            "cwd": "aztec/use-cases",
            "library": "scripts/fixtures/lib (x509_fixture.signed_ocsp)",
        },
        "inputs": inputs,
        "key_provenance": f"RSA keys derived from the public seeds 'credential-proofs synthetic {scheme} account <role> key v1' (the account fixture's chain); a local test chain, not {authority}. Anyone can sign with them.",
        "claims": {
            **claims,
            "now": NOW,
            "issued_at": issued_at,
            "session": SESSION.hex(),
        },
        "notes": [
            "The account and message are the shell address and the timed link challenge observed in TXE; the test fixture_signs_the_challenge fails with the values to use when they change.",
            "Negative cases mutate this fixture in src/test.nr.",
        ],
        "outputs": {"src/fixture.nr": hashlib.sha256(fixture.encode()).hexdigest()},
    }
    path.write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"Wrote {args.instance}/src/fixture.nr for account {account} message {message}"
    )


if __name__ == "__main__":
    main()
