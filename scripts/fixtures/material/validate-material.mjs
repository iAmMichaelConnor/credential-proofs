// Checks the credential material manifests: JSON Schema, workspace containment
// and the exact SHA-256 of referenced data files.
//
// Convention: every scheme has material/<scheme>/manifest.json and the
// directories provider-public/ (authentic issuer, attestor or verification
// material from authoritative distribution; official sandbox keys may use the
// provider-test environment), provider-test/ (explicitly published provider or
// upstream test credentials, with source and trust role) and local-test/
// (generated synthetic credentials and deliberately public test keys; a
// generated credential never becomes provider-issued because its issuer string
// resembles production). Other fixture data lives under fixtures/data/. References
// are repository-relative. Data files bind their SHA-256; maintained source,
// scripts, Markdown and generated Noir test modules are existence-only
// (schema.json `existenceOnlyPath`). Never check in production personal
// credentials or signing secrets.
//
// This verifies file integrity only. Each entry's verification record states
// the actual cryptographic method, verifier, command and result; rejected
// public samples keep a failed result, and a self-signed root does not
// authenticate itself. scripts/fixtures/generate.py updates the hashes of the
// local synthetic files it regenerates, and of no other entry; provider
// material needs its separately reviewed acquisition process
// (snapshot-trust-material.mjs for configured official JWKS sources, never a
// token's jku or x5u).
//
// node scripts/fixtures/material/validate-material.mjs
import Ajv from "ajv";
import { readFile, readdir, realpath } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const material = fileURLToPath(new URL("../../../fixtures/material/", import.meta.url));
const schema = JSON.parse(
  await readFile(resolve(material, "schema.json"), "utf8"),
);
const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(schema);
const validateReferenceSchema = ajv.compile({
  definitions: schema.definitions,
  $ref: "#/definitions/reference",
});
const existenceOnly = new RegExp(schema.definitions.existenceOnlyPath.pattern);

/** Source references are not data identities; all references must exist locally. */
export async function validateReference(workspaceRoot, ref) {
  if (!validateReferenceSchema(ref))
    throw Error(
      "Invalid material reference: " +
        JSON.stringify(validateReferenceSchema.errors),
    );
  const target = await realpath(resolve(workspaceRoot, ref.path));
  const rel = relative(workspaceRoot, target);
  if (rel.startsWith(".." + sep) || rel === "..")
    throw Error("Reference escapes workspace " + ref.path);
  // Classify the resolved path too: a source-shaped symlink cannot exempt data.
  if (
    existenceOnly.test(ref.path) &&
    existenceOnly.test(rel.split(sep).join("/"))
  )
    return;
  if (typeof ref.sha256 !== "string")
    throw Error("Data reference requires SHA256 " + ref.path);
  const actual = createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
  if (actual !== ref.sha256) throw Error("SHA256 mismatch " + ref.path);
}

async function main() {
  let count = 0;
  for (const item of await readdir(material, { withFileTypes: true })) {
    if (!item.isDirectory()) continue;
    const path = resolve(material, item.name, "manifest.json");
    const manifest = JSON.parse(await readFile(path, "utf8"));
    if (!validate(manifest))
      throw Error(path + "\n" + JSON.stringify(validate.errors));
    if (manifest.scheme !== item.name)
      throw Error("Scheme/directory mismatch " + path);
    const ids = new Set();
    for (const entry of manifest.materials) {
      if (ids.has(entry.id)) throw Error("Duplicate material id " + entry.id);
      ids.add(entry.id);
      for (const ref of [...entry.files, ...entry.verification.evidence])
        await validateReference(root, ref);
    }
    count++;
    console.log(
      manifest.scheme,
      manifest.materials.length,
      "verified references",
    );
  }
  console.log(
    "Validated",
    count,
    "material manifests against schema and data/source policy",
  );
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
)
  await main();
