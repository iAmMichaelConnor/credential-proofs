#!/usr/bin/env python3
"""Local synthetic certificate/OCSP fixtures. Never a provider-issued identity.
Use the committed public test keys to regenerate signatures for Aztec account/action.
Requires Python cryptography; no network, card operation, or provider login.

The deliberately public RSA keys in fixtures/data/x509-test-keys/<provider> reproduce the
checked-in local-test root, holder and responder certificates, OCSP statuses and
holder signatures; their subjects name SYNTHETIC TEST AUTHORITY and they must never
be used for real identities. Serials, validity dates, test clocks and PKCS#1 v1.5
signatures are deterministic, so ordinary regeneration needs these keys and never
creates replacements. --key-dir overrides the key directory for other inputs.
"""

import argparse, datetime, hashlib, json
from pathlib import Path
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

p = argparse.ArgumentParser()
p.add_argument("provider", choices=["jpki"])
p.add_argument("--account", default="01" * 32)
p.add_argument("--action", default="02" * 32)
p.add_argument("--key-dir", default=None)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = root / "fixtures/material" / a.provider / "local-test"
out.mkdir(parents=True, exist_ok=True)
key_dir = (
    Path(a.key_dir)
    if a.key_dir
    else root / "fixtures/data/x509-test-keys" / a.provider
)
from lib.x509_fixture import test_key, tlv, seq, integer, gt, signed_ocsp



def key(name):
    return test_key(key_dir, name)


ca = key("root")
holder = key("holder")
responder = key("responder")
utc = datetime.timezone.utc
before = datetime.datetime(2025, 1, 1, tzinfo=utc)
after = datetime.datetime(2033, 1, 1, tzinfo=utc)
now = datetime.datetime(2026, 10, 22, 12, tzinfo=utc)


def name(s):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SYNTHETIC TEST AUTHORITY"),
            x509.NameAttribute(NameOID.COMMON_NAME, s),
        ]
    )


ca_name = name("Not JPKI - Local Test Root")


def cert(k, subject, serial, role, policy="1.2.392.200149.8.5.1.3.30"):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_name)
        .public_key(k.public_key())
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
                [x509.PolicyInformation(ObjectIdentifier(policy), None)]
            ),
            False,
        )
    if role == 2:
        b = b.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False
        ).add_extension(x509.OCSPNoCheck(), False)
    return b.sign(ca, hashes.SHA256())


root_cert = cert(ca, ca_name, 1, 0)
leaf = cert(holder, name("Synthetic holder no personal identity"), 2, 1)
resp = cert(responder, name("Synthetic delegated OCSP responder"), 3, 2)
for n, c in [("root", root_cert), ("holder", leaf), ("responder", resp)]:
    (out / (n + ".der")).write_bytes(c.public_bytes(serialization.Encoding.DER))
    (out / (n + ".pem")).write_bytes(c.public_bytes(serialization.Encoding.PEM))
# Explicit DER fixture encoding permits a stable future test clock. No host wall
# clock or provider status is substituted into production verification.
now = datetime.datetime.fromtimestamp(1900000000, utc)


def response(
    status=ocsp.OCSPCertStatus.GOOD, serial_cert=leaf, next_delta=600, this_delta=-60
):
    return signed_ocsp(
        root_cert,
        serial_cert,
        resp,
        responder,
        now,
        status == ocsp.OCSPCertStatus.GOOD,
        next_delta,
        this_delta,
    )


ocsp_good = response()
(out / "good.ocsp.der").write_bytes(ocsp_good)
account = bytes.fromhex(a.account.removeprefix("0x"))
action = bytes.fromhex(a.action.removeprefix("0x"))
session = bytes([3]) * 32
challenge = b"MIKE_JPKI_CARD_AUTH_V1__________" + account + action + session
assert len(challenge) == 128
signature = holder.sign(challenge, padding.PKCS1v15(), hashes.SHA256())
(out / "challenge.bin").write_bytes(challenge)
(out / "holder-signature.bin").write_bytes(signature)


def arr(v):
    return (
        "["
        + ", ".join('"' + str(x) + '"' if x > 2**64 - 1 else str(x) for x in v)
        + "]"
    )


def redc(k):
    n = k.public_key().public_numbers().n
    r = (1 << (4096 + 6)) // n
    return [(r >> (120 * i)) & ((1 << 120) - 1) for i in range(18)]


def bounded(k, b, capacity):
    return [
        f"{k} = {{ storage = {arr(list(b) + [0] * (capacity - len(b)))}, len = {len(b)} }}"
    ]


spki = leaf.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
policy = {
    "anchor_class": 1,
    "root_sha256": list(
        hashlib.sha256(root_cert.public_bytes(serialization.Encoding.DER)).digest()
    ),
    "holder_spki_sha256": list(hashlib.sha256(spki).digest()),
    "max_ocsp_age": 300,
}
base = [
    f"now = {int(now.timestamp())}",
    f"account = {arr(account)}",
    f"action = {arr(action)}",
    f"session = {arr(session)}",
    "[policy]",
] + [f"{k} = {arr(v) if isinstance(v, list) else v}" for k, v in policy.items()]


def toml(leafbytes=None, responsebytes=ocsp_good, holdersig=signature, **overrides):
    b = base.copy()
    b += ["[input]"]
    for k, data, cap in [
        ("root", root_cert.public_bytes(serialization.Encoding.DER), 2048),
        (
            "certificate",
            leafbytes or leaf.public_bytes(serialization.Encoding.DER),
            2048,
        ),
        ("responder", resp.public_bytes(serialization.Encoding.DER), 2048),
        ("ocsp", responsebytes, 4096),
    ]:
        b += bounded(k, data, cap)
    b += [
        f"holder_signature = {arr(holdersig)}",
        f"root_redc = {arr(redc(ca))}",
        f"holder_redc = {arr(redc(holder))}",
        f"responder_redc = {arr(redc(responder))}",
    ]
    return "\n".join(b) + "\n"


example = root / "target/kat/jpki"
example.mkdir(parents=True, exist_ok=True)
(example / "Prover.toml").write_text(toml())
# The expiry authorise() returns: the earliest of the certificates' notAfter,
# the OCSP nextUpdate and the end of the policy's freshness window
# (thisUpdate + max_ocsp_age + 1).
good = ocsp.load_der_ocsp_response(ocsp_good)
expiry = min(
    [int(c.not_valid_after_utc.timestamp()) for c in (root_cert, leaf, resp)]
    + [
        int(good.next_update_utc.timestamp()),
        int(good.this_update_utc.timestamp()) + policy["max_ocsp_age"] + 1,
    ]
)
(example / "expiry.txt").write_text(f"{expiry}\n")
(example / "BadRedc.toml").write_text(
    toml().replace(f"holder_redc = {arr(redc(holder))}", "holder_redc = " + arr([0] * 18))
)
(example / "Revoked.toml").write_text(
    toml(responsebytes=response(ocsp.OCSPCertStatus.REVOKED))
)
other = cert(holder, name("Other synthetic serial"), 4, 1)
(example / "WrongSerial.toml").write_text(
    toml(responsebytes=response(serial_cert=other))
)
(example / "ExpiredOcsp.toml").write_text(
    toml(responsebytes=response(next_delta=-1, this_delta=-120))
)
(example / "WrongPurpose.toml").write_text(
    toml(
        leafbytes=cert(holder, leaf.subject, 2, 1, "1.2.3.4").public_bytes(
            serialization.Encoding.DER
        )
    )
)
(example / "WrongSignature.toml").write_text(
    toml(holdersig=bytes([signature[0] ^ 1]) + signature[1:])
)
(example / "WrongAction.toml").write_text(
    toml().replace("action = " + arr(action), "action = " + arr(bytes([4]) * 32))
)
(example / "WrongRoot.toml").write_text(
    toml().replace("anchor_class = 1", "anchor_class = 0")
)
metadata = {
    "synthetic": True,
    "authority": "Local test root, not JPKI",
    "now": int(now.timestamp()),
    "account": account.hex(),
    "action": action.hex(),
    "policy": policy,
    "leafSpkiSha256": hashlib.sha256(spki).hexdigest(),
    "rootSha256": hashlib.sha256(
        root_cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest(),
    "certIdHashAlgorithm": "SHA1",
    "signatureAlgorithm": "RSA2048-SHA256",
    "generator": str(Path(__file__).relative_to(root)),
}
(out / "fixture.json").write_text(json.dumps(metadata, indent=2) + "\n")
print(json.dumps(metadata, indent=2))
