// World ID 4 gate fixture: fixtures/world-id/aztec-v4-foundation.json (an OPRF nullifier
// proof bound to WorldId4Gate at a fixed test address) and aztec/world-id-v4/tests/src/fixture.nr.
//
//   node scripts/world-id/world_id4_foundation.mjs           rewrite fixture.nr from the saved proof
//   node scripts/world-id/world_id4_foundation.mjs --check   write nothing; fail if fixture.nr is stale
//   node scripts/world-id/world_id4_foundation.mjs --foundation-proof --work-dir <dir>
//                                                            create a new proof (see CONTRIBUTING.md)
//
// All modes need Node.js, the SDK built with its Groth16 peer, and nargo 1.0.0-rc.3 to
// format fixture.nr (see foundation.mjs); no Aztec toolchain. The credential, OPRF
// evaluation and registry are synthetic (world_id4_input.mjs); the proving key is the
// upstream ceremony key. Only --foundation-proof creates a proof. Its work directory
// holds the ceremony WASM and zkey and an npm install of snarkjs.
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { contextSignalHash, checkClaim } from "../../packages/credential-proofs-world-id/dist/index.js";
import {
  prepareRuntimeKey,
  prepareWorldIdGroth16,
  worldIdPrivateArguments,
} from "../../packages/credential-proofs-world-id/dist/groth16.js";
import { generateWorldId4Input } from "./world_id4_input.mjs";
import {
  NONCE,
  ROOT,
  assertBound,
  claimContext,
  options as parseOptions,
  renderFixture,
  stringify,
  writeOrCheck,
} from "./foundation.mjs";

const options = parseOptions();
const SCRIPT = "scripts/world-id/world_id4_foundation.mjs";
const FIXTURES = path.join(ROOT, "fixtures/world-id");
const OUTPUT = path.join(FIXTURES, "aztec-v4-foundation.json");
const FIXTURE_NR = path.join(ROOT, "aztec/world-id-v4/tests/src/fixture.nr");
// OPRFNullifierProof ceremony assets of world-id-protocol (trusted setup commit below).
const ASSETS = {
  "OPRFNullifierProof.wasm": "7b2abbd1ffc4075ca0380bd6890fb71a88431317f30f09f78f6ee90ef3fc7831",
  "oprfnullifierproof_final.zkey": "cef08ef106d7fdef3640a2bbb2d5e65fc2bef0c613ba65b900b65d4321a24139",
};
const TRUSTED_SETUP_COMMIT = "189abeafd2b9d7ec6729172990c8818a2717a628";
// The gate address the tests run the claim at. The proof binds it; any value works.
const ADDRESS = 12233089935524833389393161995526000720361353850321714749448522390270006640992n,
  VALID_UNTIL = 1900000000n;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

const key = JSON.parse(await fs.readFile(path.join(FIXTURES, "nullifier-v4-key.json")));
const keyHash = prepareRuntimeKey(key).keyHash;
const input = await generateWorldId4Input({
  rpId: 6n,
  action: 7n,
  signalHash: 0n,
  nonce: NONCE,
  expiry: 1800000000n,
  genesis: 9n,
});
// [root, issuer_schema_id, issuer_key[2], oprf_key[2], rp_id, action, tree_depth,
// min_expiry, min_genesis]: the gate's constructor policy.
const p = [
  input.merkle_root,
  input.issuer_schema_id,
  ...input.cred_pk,
  ...input.oprf_pk,
  input.rp_id,
  input.action,
  input.depth,
  input.current_timestamp,
  input.cred_genesis_issued_at_min,
].map(BigInt);
const policy = {
  version: "world-id-4-nullifier-v1",
  root: p[0],
  issuerSchemaId: p[1],
  issuerKey: p.slice(2, 4),
  oprfKey: p.slice(4, 6),
  rpId: p[6],
  action: p[7],
  treeDepth: p[8],
  minExpiry: p[9],
  minGenesis: p[10],
  validUntil: VALID_UNTIL,
};
const context = claimContext(ADDRESS, p[7]);

let saved;
if (options["foundation-proof"]) {
  if (!options["work-dir"]) throw Error("--foundation-proof needs --work-dir");
  const work = path.resolve(options["work-dir"]);
  for (const [name, digest] of Object.entries(ASSETS))
    if (sha(await fs.readFile(path.join(work, name))) !== digest)
      throw Error(`${name} in ${work} is not the pinned ceremony asset`);
  const snarkjs = createRequire(path.join(work, "package.json"))("snarkjs");
  const zkey = path.join(work, "oprfnullifierproof_final.zkey");
  const vk = await snarkjs.zKey.exportVerificationKey(zkey);
  for (const name of ["protocol", "curve", "nPublic", "vk_alpha_1", "vk_beta_2", "vk_gamma_2", "vk_delta_2", "IC"])
    if (JSON.stringify(key[name]) !== JSON.stringify(vk[name]))
      throw Error(`The ceremony key differs from fixtures/world-id/nullifier-v4-key.json: ${name}`);
  input.signal_hash = contextSignalHash(context);
  const expected = [
    0n,
    input.issuer_schema_id,
    ...input.cred_pk,
    input.current_timestamp,
    input.cred_genesis_issued_at_min,
    input.merkle_root,
    input.depth,
    input.rp_id,
    input.action,
    ...input.oprf_pk,
    input.signal_hash,
    input.nonce,
    input.id_commitment,
  ].map(BigInt);
  checkClaim(policy, expected, context, 100n);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    path.join(work, "OPRFNullifierProof.wasm"),
    zkey,
  );
  if (JSON.stringify(publicSignals.slice(1)) !== JSON.stringify(expected.slice(1).map(String)))
    throw Error("Unexpected upstream public input order");
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof)))
    throw Error("The new proof does not verify");
  saved = {
    description:
      "Synthetic public test credential and OPRF identity under the upstream ceremony key. No Orb enrollment.",
    context,
    policy: p,
    validUntil: VALID_UNTIL,
    keyHash,
    proof,
    publicInputs: publicSignals,
    provenance: {
      gate: "aztec/world-id-v4/contract (WorldId4Gate); context[2] is its test address",
      input: "scripts/world-id/world_id4_input.mjs",
      wasmSha256: ASSETS["OPRFNullifierProof.wasm"],
      zkeySha256: ASSETS["oprfnullifierproof_final.zkey"],
      trustedSetupCommit: TRUSTED_SETUP_COMMIT,
      snarkjs: JSON.parse(
        await fs.readFile(path.join(work, "node_modules/snarkjs/package.json")),
      ).version,
    },
  };
  await fs.writeFile(OUTPUT, stringify(saved));
  console.error(`wrote ${path.relative(ROOT, OUTPUT)}`);
} else saved = JSON.parse(await fs.readFile(OUTPUT));

if (BigInt(saved.keyHash) !== keyHash || JSON.stringify(saved.policy.map(String)) !== JSON.stringify(p.map(String)))
  throw Error("The saved proof uses another key or policy");
assertBound(saved, context, SCRIPT);
checkClaim(policy, saved.publicInputs, context, 100n);
// Prepares the hints and rejects a proof that does not verify under the key.
const args = worldIdPrivateArguments(
  await prepareWorldIdGroth16({
    version: "world-id-4-nullifier-v1",
    key,
    authorizedKeyHash: keyHash,
    proof: saved.proof,
    publicInputs: saved.publicInputs,
    context,
  }),
);
const fixture = await renderFixture(
  `// Generated by ${SCRIPT} from fixtures/world-id/aztec-v4-foundation.json; do not edit.\n`,
  [
    ["KEY", "[[u128; 3]; 46]", args.key],
    ["PROOF", "[[u128; 3]; 8]", args.proof],
    ["HINTS", "[Field; 2859]", args.hints],
    ["PUBLIC_INPUTS", "[Field; 15]", args.public_inputs],
    ["ADDRESS", "Field", ADDRESS],
    ["POLICY", "[Field; 11]", p],
    ["VALID_UNTIL", "u64", VALID_UNTIL],
    ["KEY_HASH", "Field", keyHash],
  ],
);
await writeOrCheck(FIXTURE_NR, fixture, options.check);
console.log(stringify({ address: ADDRESS, keyHash, proofCreated: Boolean(options["foundation-proof"]) }).trim());
// snarkjs leaves worker threads running.
process.exit(0);
