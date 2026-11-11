"""Independent OpenSSL-backed checks of generated GATE and LINK signature cases."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]
INSTANCE = ROOT / "aztec/use-cases/attribute-gating/zkemail"


class ZkemailAttributeFixtureTests(unittest.TestCase):
    def test_signed_purpose_controls_use_same_binding_and_key(self):
        fixture = (INSTANCE / "src/fixture.nr").read_text()
        manifest = json.loads((INSTANCE / "fixtures/manifest.json").read_text())
        claims = manifest["claims"]
        binding = int(
            re.search(r"pub global BINDING: Field = (0x[0-9a-f]+)", fixture)[1], 16
        )
        expected_body = f"CRED-PROOF-GATE:{binding:064x}\r\n"
        self.assertEqual(claims["body"], expected_body)
        self.assertEqual(claims["choice"], 7)
        self.assertEqual(claims["purpose"], "GATE")
        self.assertEqual(claims["sender"].split("@"), ["alice", claims["domain"]])
        self.assertEqual(claims["signed_at"], 4000000000 - 60)
        signature = re.search(r"signature:\s*\[([^]]+)\]", fixture)[1]
        link_signature = re.search(r"input.email.signature = \[([^]]+)\]", fixture)[1]
        public_key = (
            ROOT / "fixtures/data/synthetic-rs256-public.pem"
        )
        data = {
            "public_key": public_key.read_text(),
            "body": expected_body,
            "gate_input": claims["signing_input"],
            "link_input": claims["link_purpose_signing_input"],
            "gate_signature": re.findall(r"\d+", signature),
            "link_signature": re.findall(r"\d+", link_signature),
        }
        # Built-in node:crypto verifies the actual generated signatures, not a
        # candidate Noir hash or a merely well-formed manifest declaration.
        result = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                """
import { createHash, createVerify } from 'node:crypto';
let text = ''; for await (const chunk of process.stdin) text += chunk;
const data = JSON.parse(text);
const hash = createHash('sha256').update(data.body, 'latin1').digest('base64');
if (!data.gate_input.includes(`bh=${hash}; b=`)) throw Error('wrong GATE body hash');
const signature = limbs => {
  const n = limbs.reduce((n, limb, index) => n + (BigInt(limb) << (120n * BigInt(index))), 0n);
  return Buffer.from(n.toString(16).padStart(512, '0'), 'hex');
};
const verify = (input, limbs) => createVerify('RSA-SHA256')
  .update(Buffer.from(input, 'latin1')).verify(data.public_key, signature(limbs));
if (!verify(data.gate_input, data.gate_signature)) throw Error('invalid GATE control');
if (!verify(data.link_input, data.link_signature)) throw Error('invalid LINK control');
if (verify(data.link_input, data.gate_signature) || verify(data.gate_input, data.link_signature))
  throw Error('purpose separation failed');
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
