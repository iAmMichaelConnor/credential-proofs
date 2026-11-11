// Shared helpers of the event-proof fixture generators (zkemail_event.mjs,
// reclaim_event.mjs). They format Noir
// values and write src/fixture.nr and fixtures/manifest.json (schema
// uc-fixture-v1) of one instance. No network access, no proving.
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { formatNoir } from "./nr_format.mjs";

export const project = fileURLToPath(new URL("../../../", import.meta.url));
export const repository = fileURLToPath(
  new URL("../../../../../", import.meta.url),
);
export const credentials = "packages/credential-proofs-inputs";

/** Reference dependencies are declared by the app test package. */
export const require = createRequire(import.meta.url);

export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

/** A Noir array literal, 16 values per line. */
export function array(values, indent = "        ") {
  const v = [...values].map(String);
  const lines = [];
  for (let i = 0; i < v.length; i += 16)
    lines.push(v.slice(i, i + 16).join(", "));
  return `[\n${indent}    ${lines.join(`,\n${indent}    `)},\n${indent}]`;
}

/** Bytes as a zero-padded fixed array of `capacity`. */
export function padded(bytes, capacity, indent) {
  if (bytes.length > capacity)
    throw new Error(`value of ${bytes.length} bytes exceeds ${capacity}`);
  return array(
    [...bytes, ...new Array(capacity - bytes.length).fill(0)],
    indent,
  );
}

/** Bytes as a BoundedVec of `capacity`. */
export function bounded(bytes, capacity, indent = "        ") {
  return `BoundedVec::from_parts(${padded(bytes, capacity, indent)}, ${bytes.length})`;
}

/** A non-negative integer as `count` little-endian limbs of `bits`. */
export function limbs(value, count, bits = 120n) {
  const mask = (1n << bits) - 1n;
  return Array.from({ length: count }, (_, i) =>
    ((value >> (bits * BigInt(i))) & mask).toString(),
  );
}

/** The use-cases.json row of `<use-case>/<scheme>` and its adapter. */
export async function instanceRow(instance, adapterName) {
  const manifest = JSON.parse(
    await readFile(project + "use-cases.json", "utf8"),
  );
  const [useCase, scheme] = (instance ?? "").split("/");
  const row = manifest.instances.find(
    (i) => i.use_case === useCase && i.scheme === scheme,
  );
  if (!row) throw new Error(`${instance} is not in use-cases.json`);
  if (row.adapter !== adapterName)
    throw new Error(`${instance} does not use the ${adapterName} adapter`);
  return { useCase, scheme, adapter: manifest.adapters[adapterName] };
}

/**
 * Writes src/fixture.nr and fixtures/manifest.json. `inputs` are repository
 * paths whose sha256 the manifest records.
 */
export async function writeFixture({
  instance,
  useCase,
  scheme,
  fixture: unformatted,
  record,
  inputs,
}) {
  const directory = `${project}${instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await mkdir(directory + "src", { recursive: true });
  const fixture = formatNoir(unformatted);
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const hashes = {};
  for (const path of inputs)
    hashes[path] = sha256(await readFile(repository + path));
  const result = {
    schema: "uc-fixture-v1",
    scheme,
    use_case: useCase,
    ...record,
    inputs: hashes,
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(result, null, 2) + "\n");
  console.log(`Wrote ${instance}/src/fixture.nr`);
}
