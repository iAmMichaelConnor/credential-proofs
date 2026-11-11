import { test } from "node:test";
import assert from "node:assert/strict";
import Ajv from "ajv";
import { readFile } from "node:fs/promises";
const schema = JSON.parse(
  await readFile(new URL("../../../fixtures/material/schema.json", import.meta.url), "utf8"),
);
const validate = new Ajv({ strict: false }).compile(schema);
const manifest = JSON.parse(
  await readFile(
    new URL("../../../fixtures/material/telegram/manifest.json", import.meta.url),
    "utf8",
  ),
);
test("material schema accepts explicit public/local provenance and rejects fabricated provider origin", () => {
  assert.equal(validate(manifest), true);
  const wrong = structuredClone(manifest);
  wrong.materials[1].category = "provider-test";
  assert.equal(validate(wrong), false);
  const wrongPrivacy = structuredClone(manifest);
  wrongPrivacy.materials[0].privacy = "synthetic-subject";
  assert.equal(validate(wrongPrivacy), false);
  const cert = structuredClone(manifest);
  cert.materials[0].kind = "certificate";
  assert.equal(validate(cert), false);
  const hash = structuredClone(manifest);
  hash.materials[0].files[0].sha256 = "bad";
  assert.equal(validate(hash), false);
});
