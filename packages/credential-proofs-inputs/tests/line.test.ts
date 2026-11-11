import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { importVerifiedLine, importLineToken, LINE_ISSUER } from "credential-proofs-inputs/line";

const expected = {
  audience: "1234567890",
  subject: "U0123456789abcdef0123456789abcdef",
  nonce: "0".repeat(64),
  now: 1900000000,
};
async function fixture(issuer = LINE_ISSUER, amr: unknown = ["lineautologin"]) {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "test",
    alg: "ES256",
    use: "sig",
  };
  const token = await new SignJWT({ nonce: expected.nonce, amr })
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "test" })
    .setIssuer(issuer)
    .setAudience(expected.audience)
    .setSubject(expected.subject)
    .setExpirationTime(1900003600)
    .sign(pair.privateKey);
  return { token, jwk };
}
test("LINE ES256 imports exact channel, subject and nonce", async () => {
  const { token, jwk } = await fixture();
  const d = await importVerifiedLine(token, expected, jwk);
  assert.equal(d.now, expected.now);
  assert.equal((d.channel_id as { len: number }).len, 10);
});
test("LINE rejects wrong issuer, audience, nonce, expiry and invalid key", async () => {
  const { token, jwk } = await fixture();
  for (const patch of [
    { audience: "999" },
    { nonce: "1".repeat(64) },
    { subject: "wrong" },
    { now: 1900003600 },
  ])
    await assert.rejects(
      importVerifiedLine(token, { ...expected, ...patch }, jwk),
    );
  const wrongIssuer = await fixture("https://attacker.invalid");
  await assert.rejects(
    importVerifiedLine(wrongIssuer.token, expected, wrongIssuer.jwk),
    /iss/,
  );
  await assert.rejects(
    importVerifiedLine(token, expected, { ...jwk, kty: "RSA" }),
  );
});
test("LINE refuses HS256 before key fetch", async () => {
  const token =
    Buffer.from('{"alg":"HS256"}').toString("base64url") + ".e30.AA";
  await assert.rejects(importLineToken(token, expected), /HS256/);
});

test("LINE rejects non-string amr entries and nested shadow claims", async () => {
  const { token, jwk } = await fixture(LINE_ISSUER, [
    "pwd",
    { sub: "attacker" },
  ]);
  await assert.rejects(importVerifiedLine(token, expected, jwk), /array/);
});
