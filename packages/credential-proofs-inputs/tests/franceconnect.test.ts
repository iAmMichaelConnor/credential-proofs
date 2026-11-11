import { test } from "node:test";
import assert from "node:assert/strict";
import { CompactEncrypt, generateKeyPair, exportJWK } from "jose";
import { signSyntheticEs256, syntheticP256Jwk } from "credential-proofs-test-builders/synthetic-es256";

import { importVerifiedFranceConnect, franceConnectIssuer, importVerifiedFranceConnectV2, franceConnectV2Issuer, decryptFranceConnectJwe, type FranceConnectExpected } from "credential-proofs-inputs/franceconnect";

const expected: FranceConnectExpected = {
  environment: "production",
  minimumAcr: 2,
  audience: "synthetic-client",
  subject: "pairwise-subject",
  nonce: "0".repeat(64),
  now: 1900000000,
};
const payload = {
  iss: franceConnectIssuer("production"),
  aud: expected.audience,
  sub: expected.subject,
  nonce: expected.nonce,
  exp: expected.now + 60,
  acr: "eidas2",
  amr: ["fc", "pwd"],
};
test("FranceConnect+ signed inner JWS binds identity/context/assurance/environment", async () => {
  const token = signSyntheticEs256(payload);
  const key = syntheticP256Jwk();
  await importVerifiedFranceConnect(token, expected, key);
  for (const field of ["audience", "subject", "nonce"] as const)
    await assert.rejects(
      importVerifiedFranceConnect(
        token,
        { ...expected, [field]: "wrong" },
        key,
      ),
    );
  await assert.rejects(
    importVerifiedFranceConnect(
      token,
      { ...expected, environment: "integration" },
      key,
    ),
  );
  await assert.rejects(
    importVerifiedFranceConnect(token, { ...expected, minimumAcr: 3 }, key),
  );
  await assert.rejects(
    importVerifiedFranceConnect(
      token,
      { ...expected, now: expected.now + 60 },
      key,
    ),
  );
  for (const acr of ["eidas1", "unknown", ""])
    await assert.rejects(
      importVerifiedFranceConnect(
        signSyntheticEs256({ ...payload, acr }),
        expected,
        key,
      ),
    );
  const parts = token.split(".");
  parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
  await assert.rejects(
    importVerifiedFranceConnect(parts.join("."), expected, key),
  );
});
test("FranceConnect+ decrypts authentic local JWE then verifies original inner signature", async () => {
  const token = signSyntheticEs256(payload);
  const pair = await generateKeyPair("RSA-OAEP-256", {
    modulusLength: 2048,
    extractable: true,
  });
  const key = await exportJWK(pair.privateKey);
  key.alg = "RSA-OAEP-256";
  const encrypted = await new CompactEncrypt(Buffer.from(token))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM", cty: "JWT" })
    .encrypt(pair.publicKey);
  assert.equal(await decryptFranceConnectJwe(encrypted, key), token);
  await importVerifiedFranceConnect(
    await decryptFranceConnectJwe(encrypted, key),
    expected,
    syntheticP256Jwk(),
  );
  const wrong = await generateKeyPair("RSA-OAEP-256", {
    modulusLength: 2048,
    extractable: true,
  });
  const wrongKey = await exportJWK(wrong.privateKey);
  wrongKey.alg = "RSA-OAEP-256";
  await assert.rejects(decryptFranceConnectJwe(encrypted, wrongKey));
});

test("ordinary FranceConnectv2 eidas1 is explicit and cannot downgrade Plus", async () => {
  const normal = {
    ...expected,
    environment: "production" as const,
    minimumAcr: 1 as const,
  };
  const token = signSyntheticEs256({
    ...payload,
    iss: franceConnectV2Issuer("production"),
    acr: "eidas1",
  });
  await importVerifiedFranceConnectV2(token, normal, syntheticP256Jwk());
  await assert.rejects(
    importVerifiedFranceConnect(token, expected, syntheticP256Jwk()),
  );
  await assert.rejects(
    importVerifiedFranceConnectV2(
      token,
      { ...normal, minimumAcr: 2 },
      syntheticP256Jwk(),
    ),
  );
  await assert.rejects(
    importVerifiedFranceConnectV2(
      token,
      { ...normal, environment: "sandbox" },
      syntheticP256Jwk(),
    ),
  );
  await assert.rejects(
    importVerifiedFranceConnectV2(
      signSyntheticEs256(payload),
      normal,
      syntheticP256Jwk(),
    ),
  );
});
