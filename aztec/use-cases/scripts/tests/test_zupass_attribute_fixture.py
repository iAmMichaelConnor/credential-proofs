"""Check actual Noir ticket/holder witnesses against the POD SDK's entry tree."""

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[4]
INSTANCE = ROOT / "aztec/use-cases/attribute-gating/zupass"


def fields(source, function):
    body = source.split(f"pub fn {function}()", 1)[1].split("\npub fn ", 1)[0]
    result = dict(re.findall(r"\b(\w+):\s*(\d+)\s*,", body))
    for name in ("indices", "siblings"):
        result[name] = re.findall(
            r"true|false|\d+", re.search(rf"{name}:\s*\[([^]]+)\]", body)[1]
        )
    return result


class ZupassAttributeFixtureTests(unittest.TestCase):
    def test_same_ticket_root_independent_entries_and_signed_authorization(self):
        source = (INSTANCE / "src/fixture.nr").read_text()
        manifest = json.loads((INSTANCE / "fixtures/manifest.json").read_text())
        witnesses = {
            name: fields(source, name)
            for name in ("login", "entry", "other_root_entry")
        }
        self.assertEqual(
            witnesses["entry"]["content_id"], witnesses["login"]["content_id"]
        )
        self.assertNotEqual(
            witnesses["entry"]["content_id"],
            witnesses["other_root_entry"]["content_id"],
        )
        data = {"witnesses": witnesses, "claims": manifest["claims"]}
        # The host SDK authenticates the signatures and reconstructs both entry
        # paths from explicit source entries. It never calls the Noir verifier.
        result = subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                """
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require = createRequire(process.cwd() + '/aztec/use-cases/package.json');
const {POD, encodePublicKey, encodeSignature, verifyPODRootSignature} = require('@pcd/pod');
let text = ''; for await (const chunk of process.stdin) text += chunk;
const {witnesses: w, claims} = JSON.parse(text);
const key = (x, y) => encodePublicKey([BigInt(x), BigInt(y)]);
const signature = (rx, ry, s) => encodeSignature({R8: [BigInt(rx), BigInt(ry)], S: BigInt(s)});
const holderKey = key(w.login.holder_x, w.login.holder_y);
for (const [name, eventName] of [['entry', 'Synthetic event'], ['other_root_entry', 'Another synthetic event']]) {
  const f = w[name];
  const pod = POD.load({owner: {type:'eddsa_pubkey', value:holderKey},
      eventName: {type:'string', value:eventName}, ticketId:{type:'int', value:42n}},
      signature(f.signature_rx, f.signature_ry, f.signature_s), key(f.issuer_x, f.issuer_y));
  assert(pod.verifySignature());
  assert.equal(pod.contentID.toString(), f.content_id);
  for (const [entryName, proof] of [['ticketId', f], ...(name === 'entry' ? [['owner', w.login]] : [])]) {
    const signals = pod.content.generateEntryCircuitSignals(entryName);
    const upper = signals.proof.siblings.slice(1);
    assert.equal(signals.nameHash.toString(), proof.name_hash ?? proof.holder_name_hash);
    assert.equal(upper.length.toString(), proof.depth);
    assert.deepEqual(upper.map(String).concat(Array(8-upper.length).fill('0')), proof.siblings);
    assert.deepEqual(Array.from({length:8}, (_,i) => String(Math.floor(signals.proof.index / 2**(i+1)) % 2 === 1)), proof.indices);
  }
}
const f = w.login;
const sig = signature(f.holder_rx, f.holder_ry, f.holder_s);
const login = POD.load({_aztec_link_v1_challenge:{type:'cryptographic', value:BigInt(claims.challenge)},
    _aztec_link_v1_issued_at:{type:'int', value:BigInt(claims.issued_at)}}, sig, holderKey);
assert(login.verifySignature());
assert.equal(login.contentID.toString(), claims.login_content_id);
assert(!verifyPODRootSignature(login.contentID + 1n, sig, holderKey));
""",
            ],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
