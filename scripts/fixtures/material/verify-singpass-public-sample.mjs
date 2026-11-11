/** Offline official published staging vector; no login or token endpoint calls. */
import { readFile, writeFile } from "node:fs/promises";
import { createPublicKey, verify, createHash } from "node:crypto";
import { importVerifiedSingpass } from "credential-proofs-inputs/singpass";

import { stringifyToml } from "credential-proofs-inputs/toml";

const root = new URL("../../../", import.meta.url),
  dir = new URL("fixtures/material/singpass/", root);
const token = (
  await readFile(new URL("provider-test/id-token.txt", dir), "utf8")
).trim();
const [h, p, s] = token.split("."),
  header = JSON.parse(Buffer.from(h, "base64url")),
  claims = JSON.parse(Buffer.from(p, "base64url"));
const jwks = JSON.parse(
  await readFile(new URL("provider-public/staging-jwks.json", dir), "utf8"),
);
const matches = jwks.keys.filter((k) => k.kid === header.kid);
if (matches.length !== 1) throw Error("sample key not unique");
const key = matches[0],
  publicKey = createPublicKey({ key, format: "jwk" });
if (
  !verify(
    "sha256",
    Buffer.from(h + "." + p),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(s, "base64url"),
  )
)
  throw Error("official sample signature rejected");
const expected = {
  environment: "staging",
  minimumAssurance: 1,
  audience: claims.aud,
  subject: claims.sub,
  nonce: claims.nonce,
  now: claims.iat,
};
const document = await importVerifiedSingpass(token, expected, key);
await writeFile(
  new URL("target/kat/singpass/Prover.toml", root),
  stringifyToml(document),
);
let currentTimeRejected = false;
try {
  await importVerifiedSingpass(
    token,
    { ...expected, now: Math.floor(Date.now() / 1000) },
    key,
  );
} catch (e) {
  if (e.code === "ERR_JWT_EXPIRED") currentTimeRejected = true;
  else throw e;
}
if (!currentTimeRejected)
  throw Error("expired sample accepted at current time");
const result = {
  source:
    "Official Singpass parsing-ID-token documentation sample, unchanged compact JWS",
  issuer: claims.iss,
  kid: header.kid,
  spkiSha256: createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex"),
  jwsSha256: createHash("sha256").update(token).digest("hex"),
  signatureVerified: true,
  fixtureTime: expected.now,
  expiry: claims.exp,
  fixtureTimePolicyAccepted: true,
  currentTimeExpiredRejected: true,
  checkedAt: new Date().toISOString(),
};
console.log(JSON.stringify(result, null, 2));
