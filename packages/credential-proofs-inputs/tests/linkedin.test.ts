import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPair } from "node:crypto";
import { exportJWK, SignJWT, type JWK } from "jose";
import { importVerifiedLinkedIn } from "credential-proofs-inputs/linkedin";


const pair = await new Promise<{
  privateKey: import("node:crypto").KeyObject;
  publicKey: import("node:crypto").KeyObject;
}>((resolve, reject) => {
  generateKeyPair(
    "rsa",
    { modulusLength: 4096, publicExponent: 0x10001 },
    (error, publicKey, privateKey) =>
      error ? reject(error) : resolve({ privateKey, publicKey }),
  );
});
const jwk = (await exportJWK(pair.publicKey)) as JWK;
jwk.kid = "local-linkedin-4096";
jwk.alg = "RS256";

async function token(
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT", ...header })
    .setIssuer("https://www.linkedin.com")
    .setAudience("client")
    .setSubject("pairwise-user")
    .setIssuedAt(900)
    .setExpirationTime(2000)
    .sign(pair.privateKey);
}

const expected = { audience: "client", subject: "pairwise-user", now: 1000 };

test("LinkedIn importer accepts a synthetic bearer token with LinkedIn claims and no nonce", async () => {
  const input = await importVerifiedLinkedIn(
    await token({ profile: { label: "nested" } }),
    expected,
    jwk,
  );
  assert.deepEqual(Object.keys(input).sort(), ["audience", "now", "subject", "token", "trusted_key"]);
  assert.equal(input.now, expected.now);
  const tokenInput = input.token as Record<string, { len: number; storage: number[] }>;
  assert.equal((input.audience as { len: number }).len, 6);
  assert.equal((input.subject as { len: number }).len, 13);
  assert.equal(tokenInput.signature_b64.storage.length, 684);
});

test("LinkedIn importer requires azp to match aud", async () => {
  const jwt = await token({ azp: "other-client" });
  await assert.rejects(
    importVerifiedLinkedIn(jwt, expected, jwk),
    /azp must equal aud/,
  );
});

test("LinkedIn importer rejects JOSE header fields outside its typed Noir profile", async () => {
  await assert.rejects(
    importVerifiedLinkedIn(await token({}, { extra: "x" }), expected, jwk),
    /unsupported JWS header/,
  );
  await assert.rejects(
    importVerifiedLinkedIn(await token({}, { typ: "at+jwt" }), expected, jwk),
    /typ/,
  );
});

test("LinkedIn importer rejects non-4096-bit enrolled keys", async () => {
  const jwt = await token({});
  const short = { ...jwk, n: Buffer.alloc(256, 0xff).toString("base64url") };
  await assert.rejects(
    importVerifiedLinkedIn(jwt, expected, short),
    /exactly 4096 bits/,
  );
});

test("LinkedIn importer rejects keys whose metadata excludes signature verification", async () => {
  const jwt = await token({});
  await assert.rejects(
    importVerifiedLinkedIn(jwt, expected, { ...jwk, use: "enc" }),
    /not authorized/,
  );
  await assert.rejects(
    importVerifiedLinkedIn(jwt, expected, { ...jwk, key_ops: ["sign"] }),
    /not authorized/,
  );
  await assert.rejects(
    importVerifiedLinkedIn(jwt, expected, { ...jwk, alg: "PS256" }),
    /not authorized/,
  );
});

test("LinkedIn importer enforces standalone policy bounds before fetch", async () => {
  await assert.rejects(
    importVerifiedLinkedIn(
      "bad",
      { ...expected, subject: "s".repeat(257) },
      jwk,
    ),
    /subject must be 1\.\.256/,
  );
});
