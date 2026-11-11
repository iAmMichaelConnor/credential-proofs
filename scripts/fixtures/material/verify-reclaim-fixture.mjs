// Read-only envelope diagnostics; caller supplies the trusted attestor independently.
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { verifyReclaimEnvelope } from "credential-proofs-inputs/reclaim";

const [input, attestor, output] = process.argv.slice(2);
if (!input || !attestor)
  throw Error(
    "Usage: verify-reclaim-fixture.mjs INPUT.json TRUSTED_ATTESTOR [OUTPUT.json]",
  );
const raw = await readFile(input);
const data = JSON.parse(raw);
const body = data.claimData ?? data;
const claim = {
  ...body,
  timestampS: body.timestampS ?? body.timestamp,
  signature: data.signatures?.[0] ?? body.signature,
};
await verifyReclaimEnvelope(claim, attestor);
await assert.rejects(
  verifyReclaimEnvelope(
    { ...claim, parameters: claim.parameters + " " },
    attestor,
  ),
);
await assert.rejects(
  verifyReclaimEnvelope(
    {
      ...claim,
      timestampS:
        claim.timestampS === 0xffffffff
          ? claim.timestampS - 1
          : claim.timestampS + 1,
    },
    attestor,
  ),
);
await assert.rejects(
  verifyReclaimEnvelope(claim, "0x0000000000000000000000000000000000000001"),
);
await (output ? (x) => writeFile(output, x) : (x) => process.stdout.write(x))(
  JSON.stringify(
    {
      input,
      inputSha256: createHash("sha256").update(raw).digest("hex"),
      trustedAttestor: attestor,
      verifier: process.version + " viem2.57.8; shared reclaim.ts",
      identifierVerified: true,
      signatureVerified: true,
      changedParametersRejected: true,
      changedTimestampRejected: true,
      wrongAttestorRejected: true,
      scope:
        "Envelope verification only. No current registry/epoch authority, TLS extraction, Twitter-issued credential, inclusion freshness or account authorization claim.",
    },
    null,
    2,
  ) + "\n",
);
console.log("Reclaim fixture signature and three negative checks passed.");
