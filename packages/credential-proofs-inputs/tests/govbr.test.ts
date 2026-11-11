import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { CompactSign, importPKCS8 } from "jose";
import { importVerifiedGovbr, type GovbrExpected } from "credential-proofs-inputs/govbr";
import { createSyntheticGovbr } from "credential-proofs-test-builders/govbr";

const expected: GovbrExpected = {
  environment: "production",
  audience: "synthetic-client.gov.br",
  subject: "12345678900",
  nonce: "0".repeat(64),
  now: 1900000000,
  minimumLevel: "silver",
};
test("gov.br signed nested gold assurance satisfies silver and binds identity/session/provider", async () => {
  const x = await createSyntheticGovbr(expected);
  assert.ok(x.document.token);
  for (const field of ["audience", "subject", "nonce"] as const)
    await assert.rejects(
      importVerifiedGovbr(x.token, { ...expected, [field]: "wrong" }, x.jwk),
    );
  await assert.rejects(
    importVerifiedGovbr(
      x.token,
      { ...expected, environment: "staging" },
      x.jwk,
    ),
  );
  await assert.rejects(
    importVerifiedGovbr(
      x.token,
      { ...expected, now: expected.now + 60 },
      x.jwk,
    ),
  );
  await assert.rejects(
    importVerifiedGovbr(x.token, expected, { ...x.jwk, kid: "wrong" }),
  );
  const p = x.token.split(".");
  p[2] = (p[2]![0] === "A" ? "B" : "A") + p[2]!.slice(1);
  await assert.rejects(importVerifiedGovbr(p.join("."), expected, x.jwk));
});
test("gov.br rejects signed downgrade, duplicate assurance, numeric/unknown assurance and nested shadow escalation", async () => {
  const x = await createSyntheticGovbr(expected);
  const raw = Buffer.from(x.token.split(".")[1]!, "base64url").toString();
  const key = await importPKCS8(
    await readFile(
      new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
      "utf8",
    ),
    "RS256",
  );
  for (const bad of [
    raw.replace('"level":"gold"', '"level":"bronze"'),
    raw.replace('"level":"gold"', '"level":"bronze","other":{"level":"gold"}'),
    raw.replace('"level":"gold"', '"level":"bronze","level":"gold"'),
    raw.replace('"level":"gold"', '"level":3'),
    raw.replace('"level":"gold"', '"level":"platinum"'),
    raw.replace('"level":"gold",', ""),
    raw.replace("https://sso.acesso.gov.br/", "https://sso.acesso.gov.br"),
    raw.replace('"amr":[', '"amr":[{},'),
  ]) {
    const token = await new CompactSign(Buffer.from(bad))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    await assert.rejects(importVerifiedGovbr(token, expected, x.jwk));
  }
  const bronze = await createSyntheticGovbr(
    { ...expected, minimumLevel: "bronze" },
    "bronze",
  );
  await assert.rejects(
    importVerifiedGovbr(bronze.token, expected, bronze.jwk),
    /below policy/,
  );
});
