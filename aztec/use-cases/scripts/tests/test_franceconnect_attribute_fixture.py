"""Independent ES256 check of actual signed eIDAS values in generated fixtures."""

import base64
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]
INSTANCE = ROOT / "aztec/use-cases/attribute-gating/franceconnect"


def part(body, field):
    match = re.search(
        rf"\b{field}\s*(?:=|:)\s*BoundedVec::from_parts\(\s*\[([^]]+)\],\s*(\d+)", body
    )
    return bytes(map(int, re.findall(r"\d+", match[1])))[: int(match[2])].decode(
        "ascii"
    )


def coordinate(body, field):
    array = re.search(rf"\b{field}:\s*\[([^]]+)\]", body)[1]
    return (
        base64.urlsafe_b64encode(bytes(map(int, re.findall(r"\d+", array))))
        .decode()
        .rstrip("=")
    )


class FranceConnectAttributeFixtureTests(unittest.TestCase):
    def test_signed_three_is_not_configured_minimum_two(self):
        source = (INSTANCE / "src/fixture.nr").read_text()
        record = json.loads((INSTANCE / "fixtures/manifest.json").read_text())
        base = source.split("pub fn token()", 1)[1].split("\npub fn ", 1)[0]
        variant = source.split("pub fn assurance_3()", 1)[1].split("\npub fn ", 1)[0]
        self.assertIn("minimum_acr: 2", base)
        self.assertNotIn("minimum_acr =", variant)
        header = part(base, "header_b64")
        tokens = []
        for name, body, acr in (
            ("token", base, "eidas2"),
            ("assurance_3", variant, "eidas3"),
        ):
            payload, signature = part(body, "payload_b64"), part(body, "signature_b64")
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
            self.assertEqual(claims, record["claims"][name])
            self.assertEqual(claims["acr"], acr)
            tokens.append({"input": header + "." + payload, "signature": signature})
        data = {
            "key": {
                "kty": "EC",
                "crv": "P-256",
                "x": coordinate(base, "public_key_x"),
                "y": coordinate(base, "public_key_y"),
            },
            "tokens": tokens,
        }
        # Fixtures are signed with Noble; Node's OpenSSL-backed verifier checks
        # their actual bytes independently of both the signer and Noir.
        result = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                """
import { createPublicKey, verify } from 'node:crypto';
let text = ''; for await (const chunk of process.stdin) text += chunk;
const data = JSON.parse(text), key = createPublicKey({ key: data.key, format: 'jwk' });
for (const token of data.tokens) {
  if (!verify('sha256', Buffer.from(token.input, 'ascii'),
      { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(token.signature, 'base64url')))
    throw Error('fixture ES256 signature does not verify');
}
""",
            ],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
