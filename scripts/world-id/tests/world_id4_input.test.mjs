import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { test } from "node:test";
import { generateWorldId4Input } from "../world_id4_input.mjs";

// Optional, explicit local circuit validation; never fetches assets or proves.
// WORLD_ID4_WASM points to the pinned ceremony WASM, WORLD_ID_PROOF_WORK to
// a prepared package.json directory containing circom_runtime (via snarkjs).
const wasmPath = process.env.WORLD_ID4_WASM;
const work = process.env.WORLD_ID_PROOF_WORK;

test("test input is deterministic and respects gate policy domains", async () => {
  const input = await generateWorldId4Input();
  assert.deepEqual(await generateWorldId4Input(), input);
  assert.equal(input.rp_id, 6n);
  assert.equal(input.action, 7n);
  assert.equal(input.id_commitment, 0n);
  assert.equal(input.cred_genesis_issued_at_min, 9n);
  assert.ok(input.cred_expires_at > input.current_timestamp);
  for (const options of [
    { rpId: 1n << 64n },
    { action: 1n << 248n },
    { signalHash: -1n },
    { genesis: 1800000001n },
    { expiry: (1n << 64n) - 60n },
  ])
    await assert.rejects(generateWorldId4Input(options));
});

test(
  "pinned circuit accepts generated relations and rejects corrupt private evidence",
  {
    skip:
      !wasmPath || !work
        ? "Set WORLD_ID4_WASM and WORLD_ID_PROOF_WORK for explicit WASM validation"
        : false,
  },
  async () => {
    const wasm = await readFile(wasmPath);
    assert.equal(
      createHash("sha256").update(wasm).digest("hex"),
      "7b2abbd1ffc4075ca0380bd6890fb71a88431317f30f09f78f6ee90ef3fc7831",
    );
    const require = createRequire(path.resolve(work, "package.json"));
    const { WitnessCalculatorBuilder } = require("circom_runtime");
    const calculator = await WitnessCalculatorBuilder(wasm, {
      sanityCheck: true,
    });
    const { checkClaim, contextSignalHash } = await import(
      "../../../packages/credential-proofs-world-id/dist/index.js"
    );
    const context = [1n, 1n, 123n, 7n, 13n, 17n];
    const input = await generateWorldId4Input({
      signalHash: contextSignalHash(context),
    });
    const witness = await calculator.calculateWitness(input, true);
    assert.ok(witness[1] !== 0n, "Nullifier must be nonzero");
    assert.doesNotThrow(() =>
      checkClaim(
        {
          version: "world-id-4-nullifier-v1",
          root: input.merkle_root,
          validUntil: input.current_timestamp,
          issuerSchemaId: input.issuer_schema_id,
          issuerKey: input.cred_pk,
          oprfKey: input.oprf_pk,
          rpId: input.rp_id,
          action: input.action,
          treeDepth: input.depth,
          minExpiry: input.current_timestamp,
          minGenesis: input.cred_genesis_issued_at_min,
        },
        witness.slice(1, 16),
        context,
        100n,
      ),
    );
    // Different query domains must be signed and evaluated anew, not patched into
    // an old witness. This also covers u64/248-bit policy upper boundaries.
    const other = await generateWorldId4Input({
      rpId: (1n << 64n) - 1n,
      action: (1n << 248n) - 1n,
      signalHash: 456n,
      expiry: 1900000000n,
      genesis: 10n,
    });
    const otherWitness = await calculator.calculateWitness(other, true);
    assert.notEqual(otherWitness[1], witness[1]);
    for (const key of [
      "s",
      "cred_s",
      "dlog_s",
      "merkle_root",
      "rp_id",
      "action",
    ])
      await assert.rejects(
        calculator.calculateWitness({ ...input, [key]: input[key] + 1n }, true),
        undefined,
        `Corrupt ${key} must fail circuit assertions`,
      );
  },
);
