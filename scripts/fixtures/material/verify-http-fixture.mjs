// Shared RSA HTTP v3 envelope fixture check; application policies remain in consumers.
import { readFile, writeFile } from "node:fs/promises";
import { createPublicKey, createHash, verify, constants } from "node:crypto";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
const [input, prover, output] = process.argv.slice(2);
if (!input || !prover)
  throw Error(
    "Usage: verify-http-fixture.mjs INPUT.json PROVER.toml [OUTPUT.json]",
  );
const raw = await readFile(input);
const fixture = JSON.parse(raw);
for (const key of ["timestamp", "nonce", "body", "signature", "publicKeyPem"])
  assert.equal(typeof fixture[key], "string");
const signed = Buffer.from(
  fixture.timestamp + "\n" + fixture.nonce + "\n" + fixture.body + "\n",
);
const signature = Buffer.from(fixture.signature, "base64");
const key = createPublicKey(fixture.publicKeyPem);
assert.equal(key.asymmetricKeyType, "rsa");
assert.equal(key.asymmetricKeyDetails.modulusLength, 2048);
assert.equal(key.asymmetricKeyDetails.publicExponent, 65537n);
const options = { key, padding: constants.RSA_PKCS1_PADDING };
assert(verify("sha256", signed, options, signature));
const bad = Buffer.from(signed);
bad[0] ^= 1;
assert(!verify("sha256", bad, options, signature));
const badSignature = Buffer.from(signature);
badSignature[0] ^= 1;
assert(!verify("sha256", signed, options, badSignature));
const document = JSON.parse(
  execFileSync(
    "python3",
    [
      "-c",
      'import json,tomllib,sys;print(json.dumps(tomllib.load(open(sys.argv[1],"rb"))))',
      prover,
    ],
    { encoding: "utf8" },
  ),
);
for (const name of ["timestamp", "nonce", "body"])
  assert.equal(
    Buffer.from(document[name].storage.slice(0, document[name].len)).toString(),
    fixture[name],
  );
const integer = (limbs) =>
  limbs.reduce((n, x, i) => n + (BigInt(x) << BigInt(120 * i)), 0n);
assert.equal(
  integer(document.signature),
  BigInt("0x" + signature.toString("hex")),
);
assert.equal(
  integer(document.modulus),
  BigInt(
    "0x" +
      Buffer.from(key.export({ format: "jwk" }).n, "base64url").toString("hex"),
  ),
);
assert(
  Buffer.from(document.expected_digest).equals(
    createHash("sha256").update(signed).digest(),
  ),
);
const sha = (x) => createHash("sha256").update(x).digest("hex");
await (output ? (x) => writeFile(output, x) : (x) => process.stdout.write(x))(
  JSON.stringify(
    {
      input,
      inputSha256: sha(raw),
      prover,
      proverSha256: sha(await readFile(prover)),
      verifier: process.version + " node:crypto RSA2048/65537 PKCS1v1.5/SHA256",
      signatureVerified: true,
      changedSignedBytesRejected: true,
      changedSignatureRejected: true,
      signedInputsMatchNoir: true,
      scope:
        "Exact HTTP envelope signature and input binding; application identity/payment/freshness/action policy is separately constrained by the Noir consumer. Synthetic test material, not provider issuance.",
    },
    null,
    2,
  ) + "\n",
);
console.log(
  "RSA HTTP envelope fixture signature, two negatives and exact Noir input binding passed.",
);
