import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Needs a groth16-verifier checkout (tag v0.1.0) with its hints SDK built:
// `npm ci && npm run build` in packages/groth16-verifier-hints; GROTH16_VERIFIER names it.
const toolsDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(toolsDir, "../../../");
const fixtures = path.join(root, "fixtures/data/anon-aadhaar-v2");
const generated = path.join(root, "fixtures/anon-aadhaar/key");
const example = path.join(root, "target/kat/anon_aadhaar_v2");
if (!process.env.GROTH16_VERIFIER)
  throw new Error("set GROTH16_VERIFIER to a groth16-verifier checkout");
const hintsPath = path.join(
  path.resolve(process.env.GROTH16_VERIFIER),
  "packages/groth16-verifier-hints/dist/fixed.js",
);
const { fixedConfigurationHash, prepareFixedKey, prepareFixedHints68 } =
  await import(hintsPath);

const proof = JSON.parse(
  await fs.readFile(path.join(fixtures, "proof.json"), "utf8"),
);
const publicInputs = JSON.parse(
  await fs.readFile(path.join(fixtures, "public_signals.json"), "utf8"),
).map(BigInt);
const generatedDescriptor = JSON.parse(
  await fs.readFile(path.join(generated, "key.json"), "utf8"),
);
const descriptor = {
  schema: "groth16-fixed-global66-v1",
  verificationKey: generatedDescriptor.verificationKey,
  tPreimage: generatedDescriptor.tPreimage,
};
const configurationHash = fixedConfigurationHash(descriptor);
const key = prepareFixedKey(descriptor, configurationHash);
const hints = await prepareFixedHints68({ key, proof, publicInputs });
// The action signal the saved public test proof commits to: the keccak256 of a
// fixed test label. Upstream accepts a 256-bit numeric signal, then hashes its
// 32-byte encoding.
const actionSignal =
  0x45bfa4209d7429dfec86c2710e53e48f2b1441950a6dfea4dd09088ea13a008an;
const actionSignalBytes = Array.from({ length: 32 }, (_, i) =>
  Number((actionSignal >> BigInt((31 - i) * 8)) & 255n),
);
const timestamp = publicInputs[2];
// The public test proof is under upstream testPublicKeyHash, whose private key
// is published. Keep the fixture tied to the library constant.
const library = await fs.readFile(
  path.join(
    root,
    "noir/anon_aadhaar_v2_auth/src/lib.nr",
  ),
  "utf8",
);
const testHash = /UPSTREAM_TEST_ISSUER_KEY_HASH: Field =\s*(\d+);/.exec(
  library,
);
if (!testHash || BigInt(testHash[1]) !== publicInputs[0])
  throw new Error("fixture issuer hash is not UPSTREAM_TEST_ISSUER_KEY_HASH");

function toml(value) {
  if (Array.isArray(value)) return `[${value.map(toml).join(",")}]`;
  if (typeof value === "bigint") return JSON.stringify(String(value));
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  throw new Error(`Cannot serialize ${typeof value}`);
}

function serialize(overrides = {}) {
  const data = {
    expected_issuer_key_hash: publicInputs[0],
    expected_nullifier_seed: publicInputs[7],
    action_signal: actionSignalBytes,
    min_timestamp: timestamp,
    max_timestamp: timestamp,
    signals: publicInputs,
    raw: hints.raw,
    residue: hints.residue,
    components: hints.glvComponents,
    accumulators: hints.accumulators,
    quotient: hints.quotient,
    block_residuals: hints.blockResiduals,
    ...overrides,
  };
  return (
    Object.entries(data)
      .map(([name, value]) => `${name} = ${toml(value)}`)
      .join("\n") + "\n"
  );
}

await fs.writeFile(path.join(example, "Prover.toml"), serialize());
const wrongActionSignalBytes = actionSignalBytes.slice();
wrongActionSignalBytes[31] ^= 1;
await fs.writeFile(
  path.join(example, "ProverWrongAction.toml"),
  serialize({ action_signal: wrongActionSignalBytes }),
);
await fs.writeFile(
  path.join(example, "ProverWrongIssuer.toml"),
  serialize({ expected_issuer_key_hash: publicInputs[0] + 1n }),
);
await fs.writeFile(
  path.join(example, "ProverWrongNullifierSeed.toml"),
  serialize({ expected_nullifier_seed: publicInputs[7] + 1n }),
);
// Names describe the QR against the window: older than its start, or after its end.
await fs.writeFile(
  path.join(example, "ProverQrTooOld.toml"),
  serialize({
    min_timestamp: timestamp + 1n,
    max_timestamp: timestamp + 3600n,
  }),
);
await fs.writeFile(
  path.join(example, "ProverQrInFuture.toml"),
  serialize({
    min_timestamp: timestamp - 3600n,
    max_timestamp: timestamp - 1n,
  }),
);
const timestampAliasSignals = publicInputs.slice();
timestampAliasSignals[2] += 1n << 64n;
await fs.writeFile(
  path.join(example, "ProverTimestampAlias.toml"),
  serialize({ signals: timestampAliasSignals }),
);
const badQuotient = hints.quotient.map((limb) => limb.slice());
badQuotient[0][0] += 1n;
await fs.writeFile(
  path.join(example, "ProverBadQuotient.toml"),
  serialize({ quotient: badQuotient }),
);

const manifest = {
  schema: "anon-aadhaar-noir-fixture-v1",
  actionSignal: actionSignal.toString(),
  actionSignalHash: publicInputs[8].toString(),
  publicSignals: publicInputs.map(String),
  nullifier: publicInputs[1].toString(),
  timestamp: timestamp.toString(),
  issuerKeyHash: publicInputs[0].toString(),
  nullifierSeed: publicInputs[7].toString(),
  hintShape: {
    schema: hints.schema,
    raw: hints.raw.length,
    residue: hints.residue.length,
    components: hints.glvComponents.length,
    accumulators: hints.accumulators.length,
    quotient: hints.quotient.length,
    blockResiduals: hints.blockResiduals.length,
  },
  configurationHash: String(hints.configurationHash),
};
console.log(JSON.stringify(manifest, null, 2));
