import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { importVerifiedEs256 } from "credential-proofs-inputs/es256";

const expected = {
  issuer: "issuer",
  audience: "client",
  subject: "user",
  nonce: "nonce",
  now: 1900000000,
};
const capacity = { header: 64, payload: 256, signature: 86 };
async function fixture() {
  const key = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(key.publicKey);
  const token = await new SignJWT({ nonce: expected.nonce })
    .setProtectedHeader({ alg: "ES256" })
    .setIssuer(expected.issuer)
    .setAudience(expected.audience)
    .setSubject(expected.subject)
    .setExpirationTime(2000000000)
    .sign(key.privateKey);
  return { token, jwk };
}
test("ES256 imports a verified compact token and authenticated P256 key", async () => {
  const { token, jwk } = await fixture();
  const document = await importVerifiedEs256(token, expected, jwk, capacity);
  assert.equal(document.now, expected.now);
  assert.deepEqual((document.key as Record<string, unknown>).public_key_x, [
    ...Buffer.from(jwk.x!, "base64url"),
  ]);
});
test("ES256 rejects key confusion, wrong nonce, bad signature and capacities", async () => {
  const { token, jwk } = await fixture();
  await assert.rejects(
    importVerifiedEs256(token, expected, { ...jwk, kty: "RSA" }, capacity),
  );
  await assert.rejects(
    importVerifiedEs256(token, { ...expected, nonce: "wrong" }, jwk, capacity),
  );
  await assert.rejects(
    importVerifiedEs256(
      token.replace(/.$/, token.endsWith("A") ? "B" : "A"),
      expected,
      jwk,
      capacity,
    ),
  );
  await assert.rejects(
    importVerifiedEs256(token, expected, jwk, { ...capacity, payload: 1 }),
  );
});
