import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { importPKCS8, CompactSign } from "jose";
import { importProviderToken, importVerifiedOidc, assertFlatOidcJson } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

const expected = {
  audience: "synthetic-miargentina-client",
  subject: "opaque-miargentina-subject",
  nonce: "action-nonce",
  now: 1900000000,
};
test("Mi Argentina provider import fetches only its configured HTTPS JWKS endpoint", async (t) => {
  const fixture = await createSyntheticOidc("miargentina", expected);
  const calls: { url: string; options: RequestInit | undefined }[] = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (input: string | URL | Request, options?: RequestInit) => {
      calls.push({ url: String(input), options });
      return new Response(JSON.stringify({ keys: [fixture.jwk] }), {
        status: 200,
      });
    },
  );
  const document = await importProviderToken(
    "miargentina",
    fixture.token,
    expected,
  );
  assert.ok(document.token);
  assert.deepEqual(calls, [
    {
      url: "https://id.argentina.gob.ar/jwks",
      options: { headers: { accept: "application/json" }, redirect: "error" },
    },
  ]);
});
test("Mi Argentina synthetic signature imports with exact opaque identity and client audience", async () => {
  const x = await createSyntheticOidc("miargentina", expected);
  assert.ok(x.document.token);
  for (const field of ["audience", "subject", "nonce"] as const)
    await assert.rejects(
      importVerifiedOidc(
        "miargentina",
        x.token,
        { ...expected, [field]: "wrong" },
        x.jwk,
      ),
    );
  await assert.rejects(
    importVerifiedOidc(
      "miargentina",
      x.token,
      { ...expected, now: expected.now + 3600 },
      x.jwk,
    ),
  );
  await assert.rejects(
    importVerifiedOidc("miargentina", x.token, expected, {
      ...x.jwk,
      kid: "wrong",
    }),
  );
  const parts = x.token.split(".");
  parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
  await assert.rejects(
    importVerifiedOidc("miargentina", parts.join("."), expected, x.jwk),
  );
});
test("Mi Argentina rejects correctly signed wrong issuer, duplicate claims and an escaped backslash in the issuer", async () => {
  const x = await createSyntheticOidc("miargentina", expected);
  const pem = await readFile(
    new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  );
  const key = await importPKCS8(pem, "RS256");
  const raw = Buffer.from(x.token.split(".")[1]!, "base64url").toString();
  for (const bad of [
    raw.replace("https://id.argentina.gob.ar", "https://attacker.example"),
    raw.replace("{", '{"sub":"duplicate",'),
    raw.replace(
      "https://id.argentina.gob.ar",
      "https:\\\\/\\\\/id.argentina.gob.ar",
    ),
  ]) {
    const token = await new CompactSign(Buffer.from(bad))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    await assert.rejects(
      importVerifiedOidc("miargentina", token, expected, x.jwk),
    );
  }
  // The circuit checks and ignores nested and escaped unknown claims, and
  // decodes an escaped '/' in claims.
  for (const good of [
    raw.replace("{", '{"nested":{"iss":"https://attacker.example"},'),
    raw.replace("{", '{"escaped":"a\\\\b\\"c",'),
    raw.replace(
      "https://id.argentina.gob.ar",
      "https:\\/\\/id.argentina.gob.ar",
    ),
  ]) {
    const token = await new CompactSign(Buffer.from(good))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    assert.ok(
      (await importVerifiedOidc("miargentina", token, expected, x.jwk)).token,
    );
  }
});
