// Officially published historical Steam example, not Twitter or a current registry proof.
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { verifyReclaimEnvelope } from "credential-proofs-inputs/reclaim";

const source = await readFile(
  new URL(
    "../../../fixtures/material/reclaim/provider-test/reclaim-near-config.js",
    import.meta.url,
  ),
  "utf8",
);
const start = source.indexOf("export const SMOKE_PROOF = ");
if (start < 0) throw Error("missing public sample");
const data = JSON.parse(
  source
    .slice(start + "export const SMOKE_PROOF = ".length)
    .trim()
    .replace(/;$/, ""),
);
const claim = { ...data.claimData, signature: data.signatures[0] };
const attestor = "0x244897572368eadf65bfbc5aec98d8e5443a9072";
await verifyReclaimEnvelope(claim, attestor);
await assert.rejects(
  verifyReclaimEnvelope(
    { ...claim, parameters: claim.parameters + " " },
    attestor,
  ),
);
await assert.rejects(
  verifyReclaimEnvelope(
    { ...claim, timestampS: claim.timestampS + 1 },
    attestor,
  ),
);
await assert.rejects(
  verifyReclaimEnvelope(claim, "0x0000000000000000000000000000000000000001"),
);
const report = {
  sourceUrl:
    "https://raw.githubusercontent.com/reclaimprotocol/reclaim-near-example/4b58b12110a12261b2342248c6d91832c612a43e/src/config.js",
  officialDocumentation:
    "https://docs.reclaimprotocol.org/onchain/near/quickstart",
  sourceSha256: createHash("sha256").update(source).digest("hex"),
  verifier:
    "viem2.57.8 EIP191 recoverMessageAddress; shared packages/credential-proofs-inputs/src/reclaim.ts",
  attestor,
  identifierVerified: true,
  signatureVerified: true,
  changedParametersRejected: true,
  changedTimestampRejected: true,
  wrongAttestorRejected: true,
  trustLimit:
    "Published historical Steam extraction signed by documented tutorial attestor. Not Twitter-issued evidence, not a current epoch/registry proof, and context is not this account action. Never enroll merely because signature verifies.",
};
console.log(JSON.stringify(report, null, 2));
await writeFile(
  new URL(
    "../../../fixtures/material/reclaim/provider-test/steam-example.json",
    import.meta.url,
  ),
  JSON.stringify(data, null, 2) + "\n",
);
console.log(
  "Published Reclaim envelope signature and three negative checks passed.",
);
