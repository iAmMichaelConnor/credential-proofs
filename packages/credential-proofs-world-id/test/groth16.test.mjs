// Uses the real groth16-verifier-hints peer (see scripts/world-id/install-groth16-verifier-hints.sh);
// run with `npm run test:groth16`. `npm test` omits these adapter tests.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { prepareWorldIdGroth16, prepareRuntimeKey, fromSolidityProof, decompressWorldIdProof } from "../dist/groth16.js";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const json = async (name) =>
  JSON.parse(await fs.readFile(join(root, "fixtures/world-id", name)));
const context = ["1", "1", "2", "3", "4", "5"];

test("actual upstream World ID 3 proof uses Solidity G2 order and shared runtime68", async () => {
  const f = await json("semaphore16-inclusion.json"),
    key = await json("semaphore16-key.json");
  const proof = fromSolidityProof(f.proof.flat(2));
  const request = {
    version: "world-id-3-semaphore",
    key,
    authorizedKeyHash: prepareRuntimeKey(key).keyHash,
    proof,
    publicInputs: [
      f.root,
      f.nullifier_hash,
      f.signal_hash,
      f.external_nullifier_hash,
    ],
    context,
  };
  const h = await prepareWorldIdGroth16(request);
  assert.equal(h.schema, "groth16-runtime-global68-v1");
  assert.equal(h.inputCount, 4);
  await assert.rejects(
    prepareWorldIdGroth16({ ...request, authorizedKeyHash: 1n }),
    /Unauthorized/,
  );
  const p = [...request.publicInputs];
  p[1] = "1";
  await assert.rejects(prepareWorldIdGroth16({ ...request, publicInputs: p }));
});
test("actual upstream World ID 4 compressed proof verifies with fifteen inputs", async () => {
  const f = await json("nullifier-v4.json"),
    key = await json("nullifier-v4-key.json");
  const request = {
    version: "world-id-4-nullifier-v1",
    key,
    authorizedKeyHash: prepareRuntimeKey(key).keyHash,
    proof: decompressWorldIdProof(f.compressedProof),
    publicInputs: f.publicInputs,
    context,
  };
  const h = await prepareWorldIdGroth16(request);
  assert.equal(h.inputCount, 15);
  const p = [...f.publicInputs];
  p[6] = "1";
  await assert.rejects(prepareWorldIdGroth16({ ...request, publicInputs: p }));
  assert.throws(() =>
    decompressWorldIdProof(["0", String(1n << 256n), "0", "0"]),
  );
});
