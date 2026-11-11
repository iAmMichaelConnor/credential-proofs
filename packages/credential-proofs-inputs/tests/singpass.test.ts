import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  createECDH,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { importVerifiedSingpass, decryptSingpassJwe, type SingpassExpected } from "credential-proofs-inputs/singpass";

import { CompactEncrypt, type JWK } from "jose";
const path = new URL("../../../../fixtures/material/singpass/local-test/", import.meta.url);
async function local() {
  return {
    token: (await readFile(new URL("id-token.txt", path), "utf8")).trim(),
    key: JSON.parse(
      await readFile(new URL("issuer-key.json", path), "utf8"),
    ) as JWK,
    expected: JSON.parse(
      await readFile(new URL("policy.json", path), "utf8"),
    ) as SingpassExpected,
  };
}
function signed(
  token: string,
  change: (claims: Record<string, unknown>) => void,
) {
  const [h, p] = token.split(".");
  const claims = JSON.parse(Buffer.from(p!, "base64url").toString()) as Record<
    string,
    unknown
  >;
  change(claims);
  const d = Buffer.alloc(32);
  d[31] = 42;
  const ec = createECDH("prime256v1");
  ec.setPrivateKey(d);
  const pk = ec.getPublicKey(undefined, "uncompressed");
  const key = createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: d.toString("base64url"),
      x: pk.subarray(1, 33).toString("base64url"),
      y: pk.subarray(33).toString("base64url"),
    },
    format: "jwk",
  });
  const data =
    h + "." + Buffer.from(JSON.stringify(claims)).toString("base64url");
  return (
    data +
    "." +
    sign("sha256", Buffer.from(data), {
      key,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url")
  );
}
test("Singpass local structured profile accepts future amr value", async () => {
  const f = await local();
  await importVerifiedSingpass(f.token, f.expected, f.key);
});
test("Singpass signed actor and low assurance reject", async () => {
  const f = await local();
  await assert.rejects(
    importVerifiedSingpass(
      signed(f.token, (c) => {
        c.act = { sub: "actor" };
      }),
      f.expected,
      f.key,
    ),
    /delegated actor/,
  );
  await assert.rejects(
    importVerifiedSingpass(
      signed(f.token, (c) => {
        c.acr = "urn:singpass:authentication:loa:1";
      }),
      f.expected,
      f.key,
    ),
    /insufficient/,
  );
});
test("Singpass policy identity and future issue time reject", async () => {
  const f = await local();
  await assert.rejects(
    importVerifiedSingpass(f.token, { ...f.expected, nonce: "wrong" }, f.key),
  );
  await assert.rejects(
    importVerifiedSingpass(
      signed(f.token, (c) => {
        c.iat = f.expected.now + 1;
      }),
      f.expected,
      f.key,
    ),
    /issued time/,
  );
  await assert.rejects(
    importVerifiedSingpass(
      f.token,
      { ...f.expected, environment: "staging" },
      f.key,
    ),
  );
});
test("Singpass official published staging signature valid at fixture time, expired now", async () => {
  const base = new URL("../../../../fixtures/material/singpass/", import.meta.url);
  const token = (
    await readFile(new URL("provider-test/id-token.txt", base), "utf8")
  ).trim();
  const keys = JSON.parse(
    await readFile(new URL("provider-public/staging-jwks.json", base), "utf8"),
  ) as { keys: JWK[] };
  const c = JSON.parse(
    Buffer.from(token.split(".")[1]!, "base64url").toString(),
  );
  const expected: SingpassExpected = {
    environment: "staging",
    minimumAssurance: 1,
    audience: c.aud,
    subject: c.sub,
    nonce: c.nonce,
    now: c.iat,
  };
  await importVerifiedSingpass(token, expected, keys.keys[0]!);
  await assert.rejects(
    importVerifiedSingpass(
      token,
      { ...expected, now: 1900000000 },
      keys.keys[0]!,
    ),
  );
  await assert.rejects(
    importVerifiedSingpass(
      token,
      { ...expected, minimumAssurance: 2 },
      keys.keys[0]!,
    ),
    /insufficient/,
  );
});

test("Singpass shared JWE helper preserves exact inner JWS and authenticates cty", async () => {
  const f = await local();
  const d = Buffer.alloc(32);
  d[31] = 42;
  const jwk: JWK = {
    kty: "EC",
    crv: "P-256",
    x: f.key.x,
    y: f.key.y,
    d: d.toString("base64url"),
  };
  const recipient = createPrivateKey({ key: jwk as never, format: "jwk" });
  const encrypt = (cty: string) =>
    new CompactEncrypt(Buffer.from(f.token))
      .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256CBC-HS512", cty })
      .encrypt(createPublicKey(recipient));
  assert.equal(await decryptSingpassJwe(await encrypt("JWT"), jwk), f.token);
  await assert.rejects(
    decryptSingpassJwe(await encrypt("text/plain"), jwk),
    /cty/,
  );
});

test("Singpass requires a signed string acr and rejects singleton arrays", async () => {
  const f = await local();
  await importVerifiedSingpass(f.token, f.expected, f.key);
  for (const acr of [
    ["urn:singpass:authentication:loa:2"],
    ["urn:singpass:authentication:loa:3"],
    null,
    2,
    {},
  ])
    await assert.rejects(
      importVerifiedSingpass(
        signed(f.token, (c) => {
          c.acr = acr;
        }),
        f.expected,
        f.key,
      ),
      /acr must be a string/,
    );
});
