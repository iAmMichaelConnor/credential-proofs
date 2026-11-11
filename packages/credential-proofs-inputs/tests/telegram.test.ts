import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { importPKCS8, CompactSign } from "jose";
import { importVerifiedOidc, assertFlatOidcJson } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

const expected = {
  audience: "123456789",
  subject: "opaque-telegram-subject",
  nonce: "action-nonce",
  now: 1900000000,
};
test("Telegram synthetic signature imports with exact opaque identity and Bot ID", async () => {
  const x = await createSyntheticOidc("telegram", expected);
  assert.ok(x.document.token);
  for (const field of ["audience", "subject", "nonce"] as const)
    await assert.rejects(
      importVerifiedOidc(
        "telegram",
        x.token,
        { ...expected, [field]: "wrong" },
        x.jwk,
      ),
    );
  await assert.rejects(
    importVerifiedOidc(
      "telegram",
      x.token,
      { ...expected, now: expected.now + 3600 },
      x.jwk,
    ),
  );
  await assert.rejects(
    importVerifiedOidc("telegram", x.token, expected, {
      ...x.jwk,
      kid: "wrong",
    }),
  );
  const parts = x.token.split(".");
  parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
  await assert.rejects(
    importVerifiedOidc("telegram", parts.join("."), expected, x.jwk),
  );
});
test("Telegram rejects correctly signed wrong issuer, duplicate claims and an escaped backslash in the issuer", async () => {
  const x = await createSyntheticOidc("telegram", expected);
  const pem = await readFile(
    new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  );
  const key = await importPKCS8(pem, "RS256");
  const raw = Buffer.from(x.token.split(".")[1]!, "base64url").toString();
  for (const bad of [
    raw.replace("https://oauth.telegram.org", "https://attacker.example"),
    raw.replace("{", '{"sub":"duplicate",'),
    raw.replace(
      "https://oauth.telegram.org",
      "https:\\\\/\\\\/oauth.telegram.org",
    ),
  ]) {
    const token = await new CompactSign(Buffer.from(bad))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    await assert.rejects(
      importVerifiedOidc("telegram", token, expected, x.jwk),
    );
  }
  // The circuit checks and ignores nested and escaped unknown claims, and
  // decodes an escaped '/' in claims.
  for (const good of [
    raw.replace("{", '{"nested":{"iss":"https://attacker.example"},'),
    raw.replace("{", '{"escaped":"a\\\\b\\"c",'),
    raw.replace("https://oauth.telegram.org", "https:\\/\\/oauth.telegram.org"),
  ]) {
    const token = await new CompactSign(Buffer.from(good))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    assert.ok(
      (await importVerifiedOidc("telegram", token, expected, x.jwk)).token,
    );
  }
});

test("shared flat OIDC JSON profile: unsigned scalars, u64 selected claims", () => {
  // An unknown integer may exceed 2^64 - 1 (the circuit ignores it).
  assert.doesNotThrow(() =>
    assertFlatOidcJson(
      '{"unsigned":18446744073709551615,"big":18446744073709551616,"flag":true,"empty":null}',
    ),
  );
  for (const value of ["-1", "1.5", "1e3", "01"])
    assert.throws(() => assertFlatOidcJson('{"custom":' + value + "}"));
  for (const claim of ["exp", "nbf", "iat"])
    assert.throws(() =>
      assertFlatOidcJson('{"' + claim + '":18446744073709551616}'),
    );
});
