// World ID 3 gate fixture: fixtures/world-id/aztec-foundation.json (a Semaphore proof
// bound to WorldId3Gate at a fixed test address) and aztec/world-id-v3/tests/src/fixture.nr.
//
//   node scripts/world-id/world_id_foundation.mjs           rewrite fixture.nr from the saved proof
//   node scripts/world-id/world_id_foundation.mjs --check   write nothing; fail if fixture.nr is stale
//   node scripts/world-id/world_id_foundation.mjs --foundation-proof --work-dir <dir>
//                                                           create a new proof (see CONTRIBUTING.md)
//
// All modes need Node.js, the SDK built with its Groth16 peer, and nargo 1.0.0-rc.3 to
// format fixture.nr (see foundation.mjs); no Aztec toolchain. Replay checks the saved
// proof against the pinned key and the signal context; only --foundation-proof creates
// a proof. Its work directory holds the Semaphore depth-16 proving assets and an npm
// install of snarkjs and @semaphore-protocol/{identity,group}.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { contextSignalHash, externalNullifier } from "../../packages/credential-proofs-world-id/dist/index.js";
import {
  prepareRuntimeKey,
  prepareWorldIdGroth16,
  worldIdPrivateArguments,
} from "../../packages/credential-proofs-world-id/dist/groth16.js";
import {
  ROOT,
  assertBound,
  claimContext,
  options as parseOptions,
  renderFixture,
  stringify,
  writeOrCheck,
} from "./foundation.mjs";

const options = parseOptions();
const SCRIPT = "scripts/world-id/world_id_foundation.mjs";
const FIXTURES = path.join(ROOT, "fixtures/world-id");
const OUTPUT = path.join(FIXTURES, "aztec-foundation.json");
const FIXTURE_NR = path.join(ROOT, "aztec/world-id-v3/tests/src/fixture.nr");
// Semaphore v3 depth-16 proving assets from https://www.trusted-setup-pse.org/semaphore/16/.
const ASSETS = {
  "semaphore.wasm": "c50b9046abe5265abfd23a5b0865b0f950ec8a391a7323cd74f9468426222743",
  "semaphore.zkey": "2598459118f90d004f1473d45ddaf1097e6cc69f29a31adef76214674b3033dc",
};
// The gate address the tests run the claim at. The proof binds it; any value works.
const ADDRESS = 10463238182181560795073128494993189641381396822907388273810295971237179057340n,
  VALID_UNTIL = 1900000000n;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

const key = JSON.parse(await fs.readFile(path.join(FIXTURES, "semaphore16-key.json")));
const keyHash = prepareRuntimeKey(key).keyHash;
const scope = externalNullifier("app_world_id_aztec_test", "claim");
const context = claimContext(ADDRESS, scope);

let saved;
if (options["foundation-proof"]) {
  if (!options["work-dir"]) throw Error("--foundation-proof needs --work-dir");
  const work = path.resolve(options["work-dir"]);
  for (const [name, digest] of Object.entries(ASSETS))
    if (sha(await fs.readFile(path.join(work, name))) !== digest)
      throw Error(`${name} in ${work} is not the pinned Semaphore depth-16 asset`);
  const require = createRequire(path.join(work, "package.json"));
  const { Identity } = require("@semaphore-protocol/identity"),
    { Group } = require("@semaphore-protocol/group"),
    snarkjs = require("snarkjs");
  const vk = await snarkjs.zKey.exportVerificationKey(path.join(work, "semaphore.zkey"));
  if (prepareRuntimeKey(vk).keyHash !== keyHash)
    throw Error("The proving key differs from the pinned upstream World ID test key");
  const identity = new Identity("PUBLIC TEST IDENTITY world-id-aztec-v1");
  const group = new Group(1, 16, [identity.commitment]);
  const merkle = group.generateMerkleProof(0);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      identityTrapdoor: identity.trapdoor,
      identityNullifier: identity.nullifier,
      treePathIndices: merkle.pathIndices,
      treeSiblings: merkle.siblings,
      externalNullifier: scope,
      signalHash: contextSignalHash(context),
    },
    path.join(work, "semaphore.wasm"),
    path.join(work, "semaphore.zkey"),
  );
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof)))
    throw Error("The new proof does not verify");
  const version = async (name) =>
    JSON.parse(await fs.readFile(path.join(work, "node_modules", name, "package.json"))).version;
  saved = {
    description:
      "Public test identity and root under the upstream depth-16 World ID test key. Not a production Orb attestation.",
    context,
    root: group.root,
    validUntil: VALID_UNTIL,
    externalNullifier: scope,
    keyHash,
    proof,
    publicInputs: publicSignals,
    provenance: {
      gate: "aztec/world-id-v3/contract (WorldId3Gate); context[2] is its test address",
      artifactsUrl: "https://www.trusted-setup-pse.org/semaphore/16/",
      wasmSha256: ASSETS["semaphore.wasm"],
      zkeySha256: ASSETS["semaphore.zkey"],
      packages: Object.fromEntries(
        await Promise.all(
          ["@semaphore-protocol/identity", "@semaphore-protocol/group", "snarkjs"].map(
            async (name) => [name, await version(name)],
          ),
        ),
      ),
    },
  };
  await fs.writeFile(OUTPUT, stringify(saved));
  console.error(`wrote ${path.relative(ROOT, OUTPUT)}`);
} else saved = JSON.parse(await fs.readFile(OUTPUT));

if (BigInt(saved.keyHash) !== keyHash || BigInt(saved.externalNullifier) !== scope)
  throw Error("The saved proof uses another key or external nullifier");
assertBound(saved, context, SCRIPT);
// Prepares the hints and rejects a proof that does not verify under the key.
const args = worldIdPrivateArguments(
  await prepareWorldIdGroth16({
    version: "world-id-3-semaphore",
    key,
    authorizedKeyHash: keyHash,
    proof: saved.proof,
    publicInputs: saved.publicInputs,
    context,
  }),
);
const fixture = await renderFixture(
  `// Generated by ${SCRIPT} from fixtures/world-id/aztec-foundation.json; do not edit.\n`,
  [
    ["KEY", "[[u128; 3]; 24]", args.key],
    ["PROOF", "[[u128; 3]; 8]", args.proof],
    ["HINTS", "[Field; 2815]", args.hints],
    ["PUBLIC_INPUTS", "[Field; 4]", args.public_inputs],
    ["ADDRESS", "Field", ADDRESS],
    ["ROOT", "Field", BigInt(saved.root)],
    ["VALID_UNTIL", "u64", VALID_UNTIL],
    ["EXTERNAL_NULLIFIER", "Field", scope],
    ["KEY_HASH", "Field", keyHash],
  ],
);
await writeOrCheck(FIXTURE_NR, fixture, options.check);
console.log(stringify({ address: ADDRESS, keyHash, proofCreated: Boolean(options["foundation-proof"]) }).trim());
// snarkjs leaves worker threads running.
process.exit(0);
