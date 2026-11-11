import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { importPKCS8, CompactSign } from "jose";
import { importVerifiedOidc, assertFlatOidcJson } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

const expected = {
  audience: "123456789",
  subject: "opaque-kakao-subject",
  nonce: "action-nonce",
  now: 1900000000,
};
test("Kakao synthetic signature imports with exact opaque identity and REST app key", async () => {
  const x = await createSyntheticOidc("kakao", expected);
  assert.ok(x.document.token);
  for (const field of ["audience", "subject", "nonce"] as const)
    await assert.rejects(
      importVerifiedOidc(
        "kakao",
        x.token,
        { ...expected, [field]: "wrong" },
        x.jwk,
      ),
    );
  await assert.rejects(
    importVerifiedOidc(
      "kakao",
      x.token,
      { ...expected, now: expected.now + 3600 },
      x.jwk,
    ),
  );
  await assert.rejects(
    importVerifiedOidc("kakao", x.token, expected, { ...x.jwk, kid: "wrong" }),
  );
  const parts = x.token.split(".");
  parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
  await assert.rejects(
    importVerifiedOidc("kakao", parts.join("."), expected, x.jwk),
  );
});
test("Kakao rejects correctly signed wrong issuer, duplicate claims and an escaped backslash in the issuer", async () => {
  const x = await createSyntheticOidc("kakao", expected);
  const pem = await readFile(
    new URL("../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  );
  const key = await importPKCS8(pem, "RS256");
  const raw = Buffer.from(x.token.split(".")[1]!, "base64url").toString();
  for (const bad of [
    raw.replace("https://kauth.kakao.com", "https://attacker.example"),
    raw.replace("{", '{"sub":"duplicate",'),
    raw.replace("https://kauth.kakao.com", "https:\\\\/\\\\/kauth.kakao.com"),
  ]) {
    const token = await new CompactSign(Buffer.from(bad))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    await assert.rejects(importVerifiedOidc("kakao", token, expected, x.jwk));
  }
  // The circuit checks and ignores nested and escaped unknown claims, and
  // decodes an escaped '/' in claims.
  for (const good of [
    raw.replace("{", '{"nested":{"iss":"https://attacker.example"},'),
    raw.replace("{", '{"escaped":"a\\\\b\\"c",'),
    raw.replace("https://kauth.kakao.com", "https:\\/\\/kauth.kakao.com"),
  ]) {
    const token = await new CompactSign(Buffer.from(good))
      .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid! })
      .sign(key);
    assert.ok(
      (await importVerifiedOidc("kakao", token, expected, x.jwk)).token,
    );
  }
});
