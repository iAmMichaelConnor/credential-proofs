// Shared helpers of the account-authorisation fixture generators.
//
// Every account fixture signs the action hash that the instance test
// computes at a TXE-deployed keyless shell (`fixture_action_is_the_action`
// prints it when it changes). A generator therefore takes `--action <field
// hex>` and writes `src/fixture.nr` and `fixtures/manifest.json`
// (schema uc-fixture-v1). Keys are synthetic and derived from public seeds,
// so anyone can sign with them. No network access, no proving.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

export const project = fileURLToPath(new URL("../../../", import.meta.url));
export const repository = fileURLToPath(
  new URL("../../../../../", import.meta.url),
);
export const credentials = "packages/credential-proofs-inputs";
// Dependencies are declared by aztec/use-cases/package.json.
export const require = createRequire(
  import.meta.url,
);

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/// A 32-byte scalar derived from a public seed string.
export function seed(label) {
  return createHash("sha256").update(`credential-proofs synthetic ${label}`).digest();
}

/// Parses `--instance <use-case>/<scheme> --action <field hex>` and extra options.
export function options(extra = {}) {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      action: { type: "string" },
      ...extra,
    },
  });
  const action = (values.action ?? "")
    .replace(/^0x/, "")
    .toLowerCase()
    .padStart(64, "0");
  if (!values.instance || !/^[0-9a-f]{64}$/.test(action)) {
    throw new Error(
      "Pass --instance <use-case>/<scheme> and --action <field as hex>",
    );
  }
  values.action = action;
  return values;
}

/// A Noir array literal, 16 values per line, at the given indent.
export function array(values, indent = "        ") {
  const lines = [];
  for (let i = 0; i < values.length; i += 16) {
    lines.push(values.slice(i, i + 16).join(", "));
  }
  if (lines.length <= 1) return `[${lines.join("")}]`;
  return `[\n${indent}    ${lines.join(`,\n${indent}    `)},\n${indent}]`;
}

/// Bytes zero-padded to `capacity`, as a Noir array literal.
export function padded(bytes, capacity, indent) {
  if (bytes.length > capacity) {
    throw new Error(`value of ${bytes.length} bytes exceeds ${capacity}`);
  }
  return array(
    [...bytes, ...new Array(capacity - bytes.length).fill(0)],
    indent,
  );
}

/// A BoundedVec literal of the bytes.
export function bounded(bytes, capacity, indent) {
  return `BoundedVec::from_parts(${padded(bytes, capacity, indent)}, ${bytes.length})`;
}

export function hex32(value) {
  return Buffer.from(value.replace(/^0x/, "").padStart(64, "0"), "hex");
}

/// Writes the fixture and its manifest.
export async function write({
  instance,
  generator,
  argv,
  library,
  inputs,
  keyProvenance,
  claims,
  notes,
  fixture: unformatted,
}) {
  const [useCase, scheme] = instance.split("/");
  const manifest = JSON.parse(
    await readFile(project + "use-cases.json", "utf8"),
  );
  if (
    !manifest.instances.some(
      (i) => i.use_case === useCase && i.scheme === scheme,
    )
  ) {
    throw new Error(`${instance} is not in use-cases.json`);
  }
  const directory = `${project}${instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  const fixture = formatNoir(unformatted);
  await writeFile(directory + "src/fixture.nr", fixture);
  const hashes = {};
  for (const path of [
    ...inputs,
    `aztec/use-cases/scripts/fixtures/generators/account.mjs`,
    `aztec/use-cases/scripts/fixtures/generators/${generator}`,
  ]) {
    hashes[path] = sha256(await readFile(repository + path));
  }
  const record = {
    schema: "uc-fixture-v1",
    scheme,
    use_case: useCase,
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        `scripts/fixtures/generators/${generator}`,
        "--instance",
        instance,
        ...argv,
      ],
      cwd: "aztec/use-cases",
      library,
    },
    inputs: hashes,
    key_provenance: keyProvenance,
    claims,
    notes: [
      "The action is the instance's action hash at the TXE shell; the test fixture_action_is_the_action fails with the value to use when it changes.",
      "Negative cases mutate this fixture in src/test.nr.",
      ...(notes ?? []),
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(
    directory + "fixtures/manifest.json",
    JSON.stringify(record, null, 2) + "\n",
  );
  console.log(
    `Wrote ${instance}/src/fixture.nr for action ${argv[argv.indexOf("--action") + 1]}`,
  );
}
