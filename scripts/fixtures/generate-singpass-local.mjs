/** Explicit synthetic issuer root; authentic staging sample remains separate. */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { localP256Key } from "./lib/local-p256-key.mjs";
import { stringifyToml } from "credential-proofs-inputs/toml";

import { signSyntheticEs256 } from "credential-proofs-test-builders/synthetic-es256";

import { importVerifiedSingpass } from "credential-proofs-inputs/singpass";

const root = new URL("../../", import.meta.url),
  directory = new URL("../../fixtures/material/singpass/local-test/", import.meta.url);
await mkdir(directory, { recursive: true });
const { privateKey } = localP256Key(42),
  key = {
    ...createPublicKey(privateKey).export({ format: "jwk" }),
    alg: "ES256",
    use: "sig",
    kid: "local-synthetic-singpass",
  };
const expected = {
  environment: "production",
  minimumAssurance: 2,
  audience: "local-synthetic-singpass-client",
  subject: "local-synthetic-singpass-user",
  nonce: "0".repeat(64),
  now: 1900000000,
};
const claims = {
  iss: "https://id.singpass.gov.sg/fapi",
  aud: expected.audience,
  sub: expected.subject,
  nonce: expected.nonce,
  iat: 1899999940,
  exp: 1900003600,
  sub_type: "user",
  acr: "urn:singpass:authentication:loa:2",
  amr: ["pwd", "future-provider-method"],
  sub_attributes: { name: "SYNTHETIC LOCAL TEST" },
};
const token = signSyntheticEs256(claims, key.kid);
const document = await importVerifiedSingpass(token, expected, key);
for (const [name, value] of Object.entries({
  "id-token.txt": token + "\n",
  "issuer-key.json": JSON.stringify(key, null, 2) + "\n",
  "policy.json": JSON.stringify(expected, null, 2) + "\n",
}))
  await writeFile(new URL(name, directory), value);
const arr = (v) => "[" + v.join(",") + "]",
  bv = (v) => "BoundedVec::from_array(" + arr(v.storage.slice(0, v.len)) + ")";
function fixture(name, t, jwk, doc) {
  const parts = t.split(".");
  return `pub fn ${name}()->(AuthInput,oidc::TrustedP256Key,AuthPolicy,BoundedVec<u8,64>,u64){(AuthInput{header_b64:BoundedVec::from_array("${parts[0]}".as_bytes()),payload_b64:BoundedVec::from_array("${parts[1]}".as_bytes()),signature_b64:BoundedVec::from_array("${parts[2]}".as_bytes())},oidc::TrustedP256Key{public_key_x:${arr(doc.key.public_key_x)},public_key_y:${arr(doc.key.public_key_y)}},AuthPolicy{audience:${bv(doc.policy.audience)},subject:${bv(doc.policy.subject)},environment:${doc.policy.environment},minimum_assurance:${doc.policy.minimum_assurance}},${bv(doc.nonce)},${doc.now})}\n`;
}
const official = (
    await readFile(
      new URL(
        "fixtures/material/singpass/provider-test/id-token.txt",
        root,
      ),
      "utf8",
    )
  ).trim(),
  oClaims = JSON.parse(Buffer.from(official.split(".")[1], "base64url")),
  oKey = JSON.parse(
    await readFile(
      new URL(
        "fixtures/material/singpass/provider-public/staging-jwks.json",
        root,
      ),
      "utf8",
    ),
  ).keys[0];
const oDoc = await importVerifiedSingpass(
  official,
  {
    environment: "staging",
    minimumAssurance: 1,
    audience: oClaims.aud,
    subject: oClaims.sub,
    nonce: oClaims.nonce,
    now: oClaims.iat,
  },
  oKey,
);
await writeFile(
  new URL("target/kat/singpass/Prover.toml", root),
  stringifyToml(oDoc),
);
let noir =
  "// Official published staging vector and separate public local synthetic issuer.\nuse crate::{AuthInput,AuthPolicy};\n" +
  fixture("official_fixture", official, oKey, oDoc) +
  fixture("local_fixture", token, key, document);
for (const [name, obj] of Object.entries({
  official_payload: oClaims,
  local_payload: claims,
  delegated_payload: { ...claims, act: { sub: "another-user" } },
  future_iat_payload: { ...claims, iat: 1900000001 },
  duplicate_acr_payload: null,
})) {
  const raw =
    name === "duplicate_acr_payload"
      ? JSON.stringify(claims).replace('"acr":', '"acr":null,"acr":')
      : JSON.stringify(obj);
  noir += `pub fn ${name}()->BoundedVec<u8,768>{BoundedVec::from_array(${JSON.stringify(raw)}.as_bytes())}\n`;
}
await writeFile(
  new URL(
    "noir/singpass_auth/src/fixture.nr",
    root,
  ),
  noir,
);
console.log(
  "Generated independently verified synthetic Singpass fixture; official issuer key/sample remain separate.",
);
