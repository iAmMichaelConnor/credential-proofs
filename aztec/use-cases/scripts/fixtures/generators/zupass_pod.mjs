// Writes src/fixture.nr and fixtures/manifest.json for the Zupass POD
// attribute-gating instance: PODs signed with @pcd/pod (the version pinned in
// aztec/use-cases/package-lock.json) under public synthetic Baby Jubjub keys, and
// the LeanIMT entry proofs that the adapter checks. Nothing here is a
// Zupass-issued POD or ticket.
//
// node scripts/fixtures/generators/zupass_pod.mjs --instance attribute-gating/zupass_pod
//
// Needs `npm ci` in aztec/use-cases (@pcd/pod). No network
// access, no proving.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const credentials = "packages/credential-proofs-inputs";
const generator = "aztec/use-cases/scripts/fixtures/generators/zupass_pod.mjs";
// @pcd/pod's documented CommonJS entry (as packages/credential-proofs-inputs/src/zupass.ts).
const require = createRequire(import.meta.url);
const { POD, decodePublicKey, decodeSignature } = require("@pcd/pod");
const podPackage = JSON.parse(
  await readFile(new URL("../../../package-lock.json", import.meta.url), "utf8"),
).packages["node_modules/@pcd/pod"];

const MAX_DEPTH = 8;
// The public synthetic issuer key of packages/credential-proofs-inputs/tests/builders/src/zupass.ts,
// and a second public synthetic key for the other-issuer case. Anyone can
// sign with them.
const ISSUER_KEY =
  "0001020304050607080900010203040506070809000102030405060708090001";
const OTHER_ISSUER_KEY =
  "0909090909090909090909090909090909090909090909090909090909090909";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function witness(pod, name) {
  if (!pod.verifySignature()) throw new Error("POD signature check failed");
  const signals = pod.content.generateEntryCircuitSignals(name);
  const proof = signals.proof;
  if (proof.siblings.length < 1)
    throw new Error("POD membership proof is missing its value leaf");
  const upper = proof.siblings.slice(1);
  if (upper.length > MAX_DEPTH) throw new Error("POD entry proof too deep");
  const key = decodePublicKey(pod.signerPublicKey);
  const signature = decodeSignature(pod.signature);
  const value = pod.content.getValue(name);
  if (value.type !== "int") throw new Error(`${name} is not an int entry`);
  return {
    issuer_x: key[0].toString(),
    issuer_y: key[1].toString(),
    signature_rx: signature.R8[0].toString(),
    signature_ry: signature.R8[1].toString(),
    signature_s: signature.S.toString(),
    content_id: pod.contentID.toString(),
    name_hash: signals.nameHash.toString(),
    // The field element that the POD hashes (a negative int is p - |x|).
    value: ((value.value % FIELD_MODULUS) + FIELD_MODULUS) % FIELD_MODULUS,
    value_hash: signals.valueHash.toString(),
    entry_value: value.value.toString(),
    depth: upper.length,
    indices: Array.from(
      { length: MAX_DEPTH },
      (_, i) => Math.floor(proof.index / 2 ** (i + 1)) % 2 === 1,
    ),
    siblings: [
      ...upper.map(String),
      ...Array(MAX_DEPTH - upper.length).fill("0"),
    ],
  };
}

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function entry(fn, w, comment) {
  return `/// ${comment}
pub fn ${fn}() -> ZupassPodEntry {
    ZupassPodEntry {
        issuer_x: ${w.issuer_x},
        issuer_y: ${w.issuer_y},
        signature_rx: ${w.signature_rx},
        signature_ry: ${w.signature_ry},
        signature_s: ${w.signature_s},
        content_id: ${w.content_id},
        name_hash: ${w.name_hash},
        value: ${w.value},
        depth: ${w.depth},
        indices: [${w.indices.join(", ")}],
        siblings: [${w.siblings.join(", ")}],
    }
}
`;
}

async function main() {
  const { values } = parseArgs({ options: { instance: { type: "string" } } });
  if (values.instance !== "attribute-gating/zupass_pod")
    throw new Error("--instance attribute-gating/zupass_pod");
  const entries = {
    event: { type: "int", value: 42n },
    tier: { type: "int", value: 3n },
    owner: { type: "int", value: 7n },
    balance: { type: "int", value: -5n },
  };
  const pod = POD.sign(entries, ISSUER_KEY);
  const second = POD.sign(
    { event: { type: "int", value: 42n }, tier: { type: "int", value: 1n } },
    ISSUER_KEY,
  );
  const other = POD.sign(
    { event: { type: "int", value: 42n }, tier: { type: "int", value: 3n } },
    OTHER_ISSUER_KEY,
  );
  const cases = {
    event_entry: [witness(pod, "event"), "The base POD's `event` entry (42)."],
    tier_entry: [
      witness(pod, "tier"),
      "The base POD's `tier` entry (3): same POD, another entry.",
    ],
    negative_entry: [
      witness(pod, "balance"),
      "The base POD's `balance` entry (-5): a negative POD int.",
    ],
    second_pod_event: [
      witness(second, "event"),
      "Another POD of the same issuer with `event` 42.",
    ],
    second_pod_tier: [
      witness(second, "tier"),
      "The other POD's `tier` entry (1).",
    ],
    other_issuer_event: [
      witness(other, "event"),
      "A POD with `event` 42 from another issuer key.",
    ],
  };
  const base = cases.event_entry[0];
  const tier = cases.tier_entry[0];
  let fixture = `//! Generated by scripts/fixtures/generators/zupass_pod.mjs; see fixtures/manifest.json. Do not edit.
//! PODs signed with @pcd/pod ${podPackage.version} under public synthetic Baby Jubjub keys
//! (the synthetic key of packages/credential-proofs-inputs/tests/builders/src/zupass.ts and a second
//! one). They are not Zupass-issued PODs.
use uc_adapter_zupass::ZupassPodEntry;

/// POD name hashes of the \`event\` and \`tier\` entries.
pub global EVENT_NAME_HASH: Field = ${base.name_hash};
pub global TIER_NAME_HASH: Field = ${tier.name_hash};
/// The \`event\` and \`tier\` values of the base POD.
pub global EVENT: Field = ${base.value};
pub global TIER: Field = ${tier.value};

`;
  fixture += Object.entries(cases)
    .map(([fn, [w, comment]]) => entry(fn, w, comment))
    .join("\n");
  fixture = formatNoir(fixture);
  const directory = `${project}${values.instance}/`;
  await mkdir(`${directory}src`, { recursive: true });
  await mkdir(`${directory}fixtures`, { recursive: true });
  await writeFile(`${directory}src/fixture.nr`, fixture);
  const manifestPath = `${directory}fixtures/manifest.json`;
  const inputs = {};
  for (const path of [
    `aztec/use-cases/package-lock.json`,
    `${credentials}/src/zupass.ts`,
    generator,
  ])
    inputs[path] = sha256(await readFile(repository + path));
  const claims = {};
  for (const [fn, [w]] of Object.entries(cases))
    claims[fn] = {
      content_id: w.content_id,
      name_hash: w.name_hash,
      value: w.entry_value,
      value_hash: w.value_hash,
      issuer: [w.issuer_x, w.issuer_y],
    };
  const record = {
    schema: "uc-fixture-v1",
    scheme: "zupass_pod",
    use_case: "attribute-gating",
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/zupass_pod.mjs",
        "--instance",
        values.instance,
      ],
      cwd: "aztec/use-cases",
      library: `@pcd/pod ${podPackage.version} (EdDSA-Poseidon on Baby Jubjub, LeanIMT entry proofs)`,
    },
    inputs,
    key_provenance:
      "Public synthetic Baby Jubjub private keys written in the generator (the first is the synthetic key of packages/credential-proofs-inputs/tests/builders/src/zupass.ts); not Zupass issuer keys. Anyone can sign with them.",
    claims: {
      pods: {
        base: {
          entries: { event: "42", tier: "3", owner: "7", balance: "-5" },
        },
        second: { entries: { event: "42", tier: "1" } },
        other_issuer: { entries: { event: "42", tier: "3" } },
      },
      entries: claims,
    },
    notes: [
      "Negative cases that are not separately signed PODs mutate a valid entry in src/test.nr.",
      "The value of a negative POD int is the field element p - |x| that @pcd/pod hashes.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(
    `wrote ${values.instance}/src/fixture.nr and fixtures/manifest.json`,
  );
}

await main();
