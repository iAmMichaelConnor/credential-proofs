import assert from "node:assert/strict";
import {
  createECDH,
  createPrivateKey,
  createPublicKey,
  sign,
  type KeyObject,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { type JWK } from "jose";
import { decodeJwsJson } from "credential-proofs-inputs/jws";

import { importVerifiedOidc } from "credential-proofs-inputs/oidc";
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

import { importVerifiedEs256 } from "credential-proofs-inputs/es256";

import { entraIssuer, importVerifiedEntra } from "credential-proofs-inputs/entra";

import { importVerifiedGovbr } from "credential-proofs-inputs/govbr";
import { createSyntheticGovbr } from "credential-proofs-test-builders/govbr";

import { importVerifiedUniversity, type UniversityExpected } from "credential-proofs-inputs/university";

import { importVerifiedSingpass, type SingpassExpected } from "credential-proofs-inputs/singpass";

import { importVerifiedLine, LINE_ISSUER } from "credential-proofs-inputs/line";

import { franceConnectIssuer, franceConnectV2Issuer, importVerifiedFranceConnect, importVerifiedFranceConnectV2 } from "credential-proofs-inputs/franceconnect";


import { importVerifiedLinkedIn } from "credential-proofs-inputs/linkedin";


const base = new URL("../../../../", import.meta.url);
const rsa = createPrivateKey(
  await readFile(new URL("fixtures/data/synthetic-rs256-private.pem", base)),
);
const rsa4096 = createPrivateKey(
  await readFile(new URL("fixtures/data/synthetic-rs256-4096-private.pem", base)),
);
const scalar = Buffer.alloc(32);
scalar[31] = 42;
const ec = createECDH("prime256v1");
ec.setPrivateKey(scalar);
const point = ec.getPublicKey(undefined, "uncompressed");
const p256 = createPrivateKey({
  key: {
    kty: "EC",
    crv: "P-256",
    d: scalar.toString("base64url"),
    x: point.subarray(1, 33).toString("base64url"),
    y: point.subarray(33).toString("base64url"),
  },
  format: "jwk",
});
const jwk = (key: KeyObject): JWK => ({
  ...createPublicKey(key).export({ format: "jwk" }),
  kid: "bom-test",
  alg: key.asymmetricKeyType === "ec" ? "ES256" : "RS256",
});
const expected = {
  audience: "client",
  subject: "user",
  nonce: "nonce",
  now: 1900000000,
};
const claims = (issuer: string) => ({
  iss: issuer,
  aud: expected.audience,
  sub: expected.subject,
  nonce: expected.nonce,
  iat: expected.now,
  exp: expected.now + 300,
});
const bom = Buffer.from([239, 187, 191]);
function signed(key: KeyObject, header: Buffer, payload: Buffer): string {
  const input =
    header.toString("base64url") + "." + payload.toString("base64url");
  return (
    input +
    "." +
    sign(
      "sha256",
      Buffer.from(input),
      key.asymmetricKeyType === "ec" ? { key, dsaEncoding: "ieee-p1363" } : key,
    ).toString("base64url")
  );
}
async function checkProfile(
  key: KeyObject,
  payload: Record<string, unknown>,
  run: (token: string, key: JWK) => Promise<unknown>,
  extra: Record<string, unknown> = {},
) {
  const pub = jwk(key),
    header = Buffer.from(
      JSON.stringify({ alg: pub.alg, typ: "JWT", kid: pub.kid, ...extra }),
    ),
    body = Buffer.from(JSON.stringify(payload));
  await run(signed(key, header, body), pub);
  for (const [h, p] of [
    [Buffer.concat([bom, header]), body],
    [header, Buffer.concat([bom, body])],
  ])
    await assert.rejects(run(signed(key, h!, p!), pub), /UTF-8 BOM/);
}
test("signed JSON decoder preserves whitespace and rejects BOM and invalid UTF8", () => {
  assert.equal(decodeJwsJson(Buffer.from(' \r\n\t{"x":1}')), ' \r\n\t{"x":1}');
  assert.throws(() => decodeJwsJson(Buffer.from([255])), /encoded data/);
  assert.throws(
    () => decodeJwsJson(Buffer.concat([bom, Buffer.from("{}")])),
    /UTF-8 BOM/,
  );
});
for (const provider of [
  "google",
  "apple",
  "telegram",
  "kakao",
  "miargentina",
  "facebook",
] as const)
  test(`${provider} rejects signed header and payload BOM`, async () => {
    const f = await createSyntheticOidc(provider, expected);
    await checkProfile(
      rsa,
      JSON.parse(Buffer.from(f.token.split(".")[1]!, "base64url").toString()),
      (token, key) => importVerifiedOidc(provider, token, expected, key),
    );
  });
test("ES256 and LINE reject signed header and payload BOM", async () => {
  await checkProfile(p256, claims("issuer"), (token, key) =>
    importVerifiedEs256(token, { ...expected, issuer: "issuer" }, key, {
      header: 192,
      payload: 1024,
      signature: 86,
    }),
  );
  const policy = { ...expected, audience: "1234567890" };
  await checkProfile(
    p256,
    { ...claims(LINE_ISSUER), aud: policy.audience },
    (token, key) => importVerifiedLine(token, policy, key),
  );
});
test("Entra rejects signed header and payload BOM", async () => {
  const policy = {
    ...expected,
    tenant: "12345678-1234-1234-1234-123456789abc",
  };
  await checkProfile(
    rsa,
    { ...claims(entraIssuer(policy.tenant)), tid: policy.tenant, ver: "2.0" },
    (token, key) => importVerifiedEntra(token, policy, key),
  );
});
test("gov.br rejects signed header and payload BOM", async () => {
  const policy = {
    ...expected,
    environment: "production" as const,
    minimumLevel: "silver" as const,
  };
  const f = await createSyntheticGovbr(policy);
  await checkProfile(
    rsa,
    JSON.parse(Buffer.from(f.token.split(".")[1]!, "base64url").toString()),
    (token, key) => importVerifiedGovbr(token, policy, key),
  );
});
for (const profile of ["singpass", "university"] as const)
  test(`${profile} rejects signed header and payload BOM`, async () => {
    const dir = new URL(`fixtures/material/${profile}/local-test/`, base);
    const token = (await readFile(new URL("id-token.txt", dir), "utf8")).trim();
    const raw = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString(),
    ) as Record<string, unknown>;
    const policy = JSON.parse(
      await readFile(new URL("policy.json", dir), "utf8"),
    );
    await checkProfile(
      profile === "singpass" ? p256 : rsa,
      raw,
      (value, key) =>
        profile === "singpass"
          ? importVerifiedSingpass(value, policy as SingpassExpected, key)
          : importVerifiedUniversity(value, policy as UniversityExpected, key),
    );
  });
test("FranceConnect profiles reject signed header and payload BOM", async () => {
  const policy = {
    ...expected,
    environment: "production" as const,
    minimumAcr: 2 as const,
  };
  await checkProfile(
    p256,
    { ...claims(franceConnectIssuer("production")), acr: "eidas2" },
    (token, key) => importVerifiedFranceConnect(token, policy, key),
  );
  await checkProfile(
    p256,
    { ...claims(franceConnectV2Issuer("production")), acr: "eidas2" },
    (token, key) => importVerifiedFranceConnectV2(token, policy, key),
  );
});
test("LinkedIn rejects signed header and payload BOM", async () => {
  await checkProfile(
    rsa4096,
    claims("https://www.linkedin.com"),
    (token, key) => importVerifiedLinkedIn(token, expected, key),
  );
});
