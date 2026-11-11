import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { importVerifiedPhilSys } from "credential-proofs-inputs/philsys";

const base = new URL("../../../../fixtures/material/philsys/local-test/", import.meta.url),
  raw = readFileSync(new URL("synthetic-legacy-qr.json", base), "utf8"),
  material = JSON.parse(
    readFileSync(new URL("synthetic-issuer-key.json", base), "utf8"),
  ),
  key = Buffer.from(material.publicKeyBase64, "base64");
test("legacy PhilSys exact synthetic issuer relation and field ordering", () => {
  const imported = importVerifiedPhilSys(raw, key);
  assert.equal(imported.auth.pcn.length, 19);
  assert.equal(imported.policy.credential_digest.length, 32);
  const parsed = JSON.parse(raw);
  const reordered = JSON.stringify({
    signature: parsed.signature,
    alg: parsed.alg,
    subject: parsed.subject,
    Issuer: parsed.Issuer,
    DateIssued: parsed.DateIssued,
  });
  assert.deepEqual(
    importVerifiedPhilSys(reordered, key).policy,
    imported.policy,
  );
});
test("PhilSys rejects copied mutations, duplicate names, wrong issuer/algorithm, Unicode and trust key", () => {
  const parsed = JSON.parse(raw);
  parsed.subject.PCN = "0000-0000-0000-0001";
  assert.throws(
    () => importVerifiedPhilSys(JSON.stringify(parsed), key),
    /verification failed/,
  );
  assert.throws(
    () =>
      importVerifiedPhilSys(
        raw.replace('"Issuer": "PSA"', '"Issuer":"PSA","Issuer":"PSA"'),
        key,
      ),
    /duplicate/,
  );
  assert.throws(
    () => importVerifiedPhilSys(raw.replace('"EDDSA"', '"ES256"'), key),
    /algorithm/,
  );
  assert.throws(
    () => importVerifiedPhilSys(raw.replace("SYNTHETIC", "\u{1F600}"), key),
    /Latin1/,
  );
  assert.throws(() => importVerifiedPhilSys(raw, Buffer.alloc(32)));
});
test("PhilSys circuit fields hold the signed spelling of an enye", () => {
  const seed = Buffer.from(
    JSON.parse(readFileSync(new URL("synthetic-issuer-key.json", base), "utf8"))
      .privateSeedHex,
    "hex",
  );
  const sk = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const parsed = JSON.parse(raw);
  delete parsed.signature;
  parsed.subject.lName = "PE\u00d1A";
  parsed.subject.fName = "ni\u00f1o";
  const message = Buffer.from(
    JSON.stringify(parsed, null, 2).replace(/\u00f1|\u00d1/g, "?"),
    "latin1",
  );
  const imported = importVerifiedPhilSys(
    JSON.stringify({
      ...parsed,
      signature: sign(null, message, sk).toString("base64"),
    }),
    key,
  );
  assert.deepEqual(imported.auth.last_name, [...Buffer.from("PE?A")]);
  assert.deepEqual(imported.auth.first_name, [...Buffer.from("ni?o")]);
  for (const key of [
    "date_issued",
    "suffix",
    "last_name",
    "first_name",
    "middle_name",
    "sex",
    "blood_finger",
    "date_of_birth",
    "place_of_birth",
    "pcn",
  ] as const) {
    const field = imported.auth[key];
    assert.ok(!field.includes(241) && !field.includes(209), key);
  }
  assert.deepEqual(imported.policy.credential_digest, [
    ...createHash("sha256").update(message).digest(),
  ]);
});
