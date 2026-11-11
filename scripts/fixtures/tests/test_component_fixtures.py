"""Independent component-scenario checks; host computation only, no Noir or proofs."""

import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/fixtures/generate-component-fixtures.mjs"
READY = (ROOT / "node_modules/@pcd/pod").is_dir() and (
    ROOT / "packages/credential-proofs-inputs/dist/src/toml.js"
).is_file()


def active(value):
    assert all(byte == 0 for byte in value["storage"][value["len"] :])
    return bytes(value["storage"][: value["len"]])


def integer(limbs):
    return sum(int(value) << (120 * i) for i, value in enumerate(limbs))


@unittest.skipUnless(READY, "needs `npm ci && npm run build` at the repository root")
class ComponentFixturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        subprocess.run(
            ["node", str(SCRIPT), str(cls.output)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        cls.paths = sorted((cls.output / "target/kat").glob("*/Prover.toml"))
        cls.docs = {p.parent.name: tomllib.loads(p.read_text()) for p in cls.paths}

    def test_deterministic_outputs(self):
        first = {p: p.read_bytes() for p in self.paths}
        subprocess.run(
            ["node", str(SCRIPT), str(self.output)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(first, {p: p.read_bytes() for p in self.paths})
        self.assertEqual(
            set(self.docs),
            {"base64url", "json_member_batch", "es256_jwt", "p256_black_box", "rsa_signature_compat"},
        )

    def test_decoder_return_and_json_spans_have_independent_references(self):
        encoded = active(self.docs["base64url"]["encoded"])
        decoded = base64.b64decode(encoded + b"==", altchars=b"-_", validate=True)
        self.assertEqual(base64.urlsafe_b64encode(decoded).rstrip(b"="), encoded)
        document = active(self.docs["json_member_batch"]["document"]).decode()
        self.assertFalse(self.docs["json_member_batch"]["brokered"])
        self.assertEqual(document.count('"idp":'), 2)
        self.assertEqual(json.loads(document)["azp"], "wrong")
        for name, present, span in zip(
            ["iss", "aud", "sub", "nonce", "exp", "iat", "nbf", "idp"],
            self.docs["json_member_batch"]["present"],
            self.docs["json_member_batch"]["expected"],
        ):
            if name in ("nbf", "idp"):
                self.assertFalse(present)
                self.assertEqual(span, {"start": 0, "end": 0, "kind": 0})
            else:
                start = re.search('"' + name + '":', document).end()
                value, length = json.JSONDecoder().raw_decode(document[start:])
                self.assertTrue(present)
                self.assertEqual(
                    span,
                    {
                        "start": start,
                        "end": start + length,
                        "kind": ord(document[start]),
                    },
                )
                self.assertEqual(value, json.loads(document)[name])

    def test_rsa_digest_and_signature_match_independent_pkcs1_reference(self):
        d = self.docs["rsa_signature_compat"]
        message = active(d["body"])
        digest = hashlib.sha256(message).digest()
        self.assertEqual(bytes(d["expected_digest"]), digest)
        decoded = pow(integer(d["signature"]), 65537, integer(d["modulus"])).to_bytes(
            256, "big"
        )
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
        self.assertEqual(
            decoded,
            b"\x00\x01" + b"\xff" * (253 - len(digest_info)) + b"\x00" + digest_info,
        )

    def test_p256_signatures_verify_with_independent_node_crypto(self):
        code = """const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const d=JSON.parse(fs.readFileSync(0,'utf8'));const b=v=>Buffer.from(v.storage.slice(0,v.len));
const message=Buffer.concat([b(d.jwt.token.header_b64),Buffer.from('.'),b(d.jwt.token.payload_b64)]);
const key=crypto.createPublicKey({key:{kty:'EC',crv:'P-256',x:Buffer.from(d.component.x).toString('base64url'),y:Buffer.from(d.component.y).toString('base64url')},format:'jwk'});
const raw=Buffer.from(b(d.jwt.token.signature_b64).toString(),'base64url');
assert(crypto.verify('sha256',message,{key,dsaEncoding:'ieee-p1363'},raw));
assert(crypto.verify('sha256',message,{key,dsaEncoding:'ieee-p1363'},Buffer.from(d.component.signature)));
assert.deepEqual([...crypto.createHash('sha256').update(message).digest()],d.component.digest);
assert(!crypto.verify('sha256',Buffer.from('changed'),{key,dsaEncoding:'ieee-p1363'},raw));"""
        subprocess.run(
            ["node", "-e", code],
            input=json.dumps(
                {"jwt": self.docs["es256_jwt"], "component": self.docs["p256_black_box"]}
            ),
            text=True,
            check=True,
            capture_output=True,
            timeout=15,
        )
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        raw = base64.urlsafe_b64decode(
            active(self.docs["es256_jwt"]["token"]["signature_b64"]) + b"=="
        )
        low = bytes(self.docs["p256_black_box"]["signature"])
        self.assertEqual(low[:32], raw[:32])
        self.assertEqual(
            int.from_bytes(low[32:], "big"),
            min(
                int.from_bytes(raw[32:], "big"), order - int.from_bytes(raw[32:], "big")
            ),
        )

    def test_scalar_equation_keeps_valid_identity_signature(self):
        fixture = json.loads((ROOT / "fixtures/data/zupass/fixture.json").read_text())
        x, y = (int(fixture["issuer"][axis]) for axis in ("x", "y"))
        p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
        self.assertEqual((168700 * x * x + y * y - 1 - 168696 * x * x * y * y) % p, 0)
        self.assertNotEqual((x, y), (0, 1))
        x8, y8 = x, y
        for _ in range(3):
            product = 168696 * x8 * x8 * y8 * y8 % p
            x8, y8 = (
                2 * x8 * y8 * pow(1 + product, -1, p) % p,
                (y8 * y8 - 168700 * x8 * x8) * pow(1 - product, -1, p) % p,
            )
        self.assertNotEqual((x8, y8), (0, 1))
