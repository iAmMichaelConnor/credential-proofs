#!/usr/bin/env python3
"""Convert the saved Google/Apple synthetic signed vectors without changing claims or keys."""

import base64
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
record = json.loads((ROOT / "fixtures/data/oidc-synthetic-fixtures.json").read_text())
modulus = sum(
    int(v) << (120 * i)
    for i, v in enumerate(record["trusted_rsa_key"]["modulus_limbs"])
)
n = base64.urlsafe_b64encode(modulus.to_bytes(256, "big")).rstrip(b"=").decode()
# JSON numbers are parsed by Python so the 120-bit saved limbs retain every bit.
node = r"""import{readFileSync,writeFileSync}from'node:fs';
import{importVerifiedOidc}from'credential-proofs-inputs/oidc';
import{stringifyToml}from'credential-proofs-inputs/toml';
const input=JSON.parse(readFileSync(0,'utf8'));
for(const provider of ['google','apple']){
 const document=await importVerifiedOidc(provider,input.tokens[provider],input.expected,input.jwk);
 writeFileSync(`target/kat/${provider}/Prover.toml`,
 '# Synthetic local issuer fixture, not a Google/Apple-issued credential.\n'+stringifyToml(document));
}"""
value = {
    "expected": {**record["expected"], "now": record["now"]},
    "jwk": {
        "kty": "RSA",
        "alg": "RS256",
        "kid": "synthetic-test-key",
        "n": n,
        "e": "AQAB",
    },
    "tokens": {
        name: record[name]["token"]["compact_jwt"] for name in ("google", "apple")
    },
}
subprocess.run(
    ["node", "--input-type=module", "-e", node],
    cwd=ROOT,
    input=json.dumps(value),
    text=True,
    check=True,
)
