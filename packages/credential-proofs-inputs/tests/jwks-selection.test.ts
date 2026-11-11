import { test } from "node:test";
import assert from "node:assert/strict";
import { selectVerificationJwk } from "credential-proofs-inputs/jws";

// One JWKS selection rule for every importer.
const rsa = { kty: "RSA", n: "AQAB", e: "AQAB" };
const rs256 = { kid: "k", kty: "RSA" as const, alg: "RS256" as const };
test("selects the one signature key and ignores encryption and private keys under the same kid", () => {
  const sig = { ...rsa, kid: "k", use: "sig", alg: "RS256" };
  for (const other of [
    { ...rsa, kid: "k", use: "enc" },
    { ...rsa, kid: "k", alg: "RSA-OAEP" },
    { ...rsa, kid: "k", key_ops: ["encrypt"] },
    { ...rsa, kid: "k", d: "AQAB" },
    { ...rsa, kid: "other" },
    { kty: "EC", crv: "P-256", kid: "k" },
  ])
    assert.equal(selectVerificationJwk([sig, other], rs256), sig);
  assert.equal(
    selectVerificationJwk([{ ...rsa, kid: "k", key_ops: ["verify"] }], rs256)
      .kid,
    "k",
  );
});
test("rejects a missing, ambiguous or unusable key", () => {
  for (const keys of [
    [],
    [
      { ...rsa, kid: "k" },
      { ...rsa, kid: "k", use: "sig" },
    ],
    [{ ...rsa, kid: "k", use: "enc" }],
    [{ ...rsa, kid: "k", alg: "RS512" }],
  ])
    assert.throws(() => selectVerificationJwk(keys, rs256), /exactly one/);
  assert.throws(() => selectVerificationJwk(undefined, rs256), /no keys/);
  assert.throws(
    () =>
      selectVerificationJwk([{ ...rsa, kid: "k" }], {
        ...rs256,
        kid: undefined,
      }),
    /kid is required/,
  );
});
test("EC selection checks the curve, and requireAlg keeps an alg-less key out", () => {
  const ec = { kty: "EC", crv: "P-256", kid: "k" };
  const es = {
    kid: "k",
    kty: "EC" as const,
    crv: "P-256",
    alg: "ES256" as const,
  };
  assert.equal(selectVerificationJwk([ec, { ...ec, crv: "P-384" }], es), ec);
  assert.throws(
    () => selectVerificationJwk([ec], { ...es, requireAlg: true }),
    /exactly one/,
  );
  assert.equal(
    selectVerificationJwk([{ ...ec, alg: "ES256" }], {
      ...es,
      requireAlg: true,
    }).alg,
    "ES256",
  );
});
