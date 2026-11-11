/** Public repository RSA fixture, never CILogon/university-issued. */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { SignJWT, CompactSign, importPKCS8, importSPKI, exportJWK } from "jose";
import { importVerifiedUniversity, CILOGON } from "credential-proofs-inputs/university";

import { stringifyToml, boundedBytes } from "credential-proofs-inputs/toml";

const root = new URL("../../", import.meta.url),
  seedDir = new URL("../../fixtures/data/", import.meta.url);
const privateKey = await importPKCS8(
    await readFile(new URL("synthetic-rs256-private.pem", seedDir), "utf8"),
    "RS256",
  ),
  jwk = {
    ...(await exportJWK(
      await importSPKI(
        await readFile(new URL("synthetic-rs256-public.pem", seedDir), "utf8"),
        "RS256",
      ),
    )),
    kid: "local-synthetic-university",
    alg: "RS256",
    use: "sig",
  };
const expected = {
  mode: "cilogon",
  issuer: CILOGON.issuer,
  audience: "cilogon:/client_id/local-synthetic-university",
  subject: "http://cilogon.org/serverA/users/local-synthetic-university",
  nonce: "0".repeat(64),
  now: 1900000000,
  institutionalIdp: "urn:mace:incommon:uiuc.edu",
};
const claims = {
  iss: expected.issuer,
  aud: expected.audience,
  sub: expected.subject,
  nonce: expected.nonce,
  iat: 1899999940,
  exp: 1900003600,
  idp: expected.institutionalIdp,
  affiliation: "student@example.edu;member@example.edu",
  groups: ["synthetic-group"],
};
const header = { alg: "RS256", typ: "JWT", kid: jwk.kid };
const token = await new SignJWT(claims)
  .setProtectedHeader(header)
  .sign(privateKey);
const document = await importVerifiedUniversity(token, expected, jwk);
const dir = new URL("../../fixtures/material/university/local-test/", import.meta.url);
await mkdir(dir, { recursive: true });
for (const [name, data] of Object.entries({
  "id-token.txt": token + "\n",
  "issuer-key.json": JSON.stringify(jwk, null, 2) + "\n",
  "policy.json": JSON.stringify(expected, null, 2) + "\n",
}))
  await writeFile(new URL(name, dir), data);
await writeFile(
  new URL("target/kat/university/Prover.toml", root),
  stringifyToml(document),
);
await writeFile(
  new URL("target/kat/university_claims/Prover.toml", root),
  stringifyToml({
    payload: boundedBytes(Buffer.from(token.split(".")[1], "base64url"), 1536),
    policy: document.policy,
    nonce: document.nonce,
    now: document.now,
    brokered: true,
  }),
);
// Direct (not brokered) vectors. Direct mode never reads institutional_idp, so the relations require it empty.
const directIssuer = "https://oidc.example.edu",
  directToken = await new SignJWT({ ...claims, iss: directIssuer })
    .setProtectedHeader(header)
    .sign(privateKey);
const direct = await importVerifiedUniversity(
  directToken,
  { ...expected, mode: "direct", issuer: directIssuer, institutionalIdp: "" },
  jwk,
);
const directWithIdp = {
  ...direct,
  policy: {
    ...direct.policy,
    institutional_idp: boundedBytes(
      Buffer.from(expected.institutionalIdp),
      256,
    ),
  },
};
const claimsInput = (d) => ({
  payload: boundedBytes(
    Buffer.from(directToken.split(".")[1], "base64url"),
    1536,
  ),
  policy: d.policy,
  nonce: d.nonce,
  now: d.now,
  brokered: false,
});
const directCases = [
  { name: "Direct", success: true },
  {
    name: "DirectWithIdp",
    reason: "institutional idp must be empty in direct mode",
  },
];
for (const [example, shape] of [
  ["university", (d) => d],
  ["university_claims", claimsInput],
]) {
  for (const [name, d] of [
    ["Direct", direct],
    ["DirectWithIdp", directWithIdp],
  ])
    await writeFile(
      new URL(
        "target/kat/" + example + "/" + name + ".toml",
        root,
      ),
      stringifyToml(shape(d)),
    );
  await writeFile(
    new URL("target/kat/" + example + "/vectors.json", root),
    JSON.stringify({ cases: directCases }, null, 2) + "\n",
  );
}
const arr = (x) => "[" + x.join(",") + "]",
  bv = (x) => "BoundedVec::from_array(" + arr(x.storage.slice(0, x.len)) + ")";
function fixture(name, t) {
  const parts = t.split(".");
  return `pub fn ${name}()->(AuthInput,TrustedRsaKey,AuthPolicy,BoundedVec<u8,64>){(AuthInput{header_b64:BoundedVec::from_array("${parts[0]}".as_bytes()),payload_b64:BoundedVec::from_array("${parts[1]}".as_bytes()),signature_b64:BoundedVec::from_array("${parts[2]}".as_bytes())},TrustedRsaKey{modulus_limbs:${arr(document.trusted_key.modulus_limbs)},redc_params_limbs:${arr(document.trusted_key.redc_params_limbs)}},AuthPolicy{issuer:${bv(document.policy.issuer)},audience:${bv(document.policy.audience)},subject:${bv(document.policy.subject)},institutional_idp:${bv(document.policy.institutional_idp)}},${bv(document.nonce)})}\n`;
}
let noir =
  "// Generated synthetic local issuer root, never provider-issued.\nuse crate::{AuthInput,AuthPolicy};\nuse oidc::TrustedRsaKey;\n" +
  fixture("fixture", token);
noir +=
  "pub fn fixture_payload()->BoundedVec<u8,512>{BoundedVec::from_array(" +
  JSON.stringify(JSON.stringify(claims)) +
  ".as_bytes())}\n";
const variants = {
  direct_issuer: JSON.stringify({ ...claims, iss: "https://oidc.example.edu" }),
  missing_idp: (() => {
    const c = { ...claims };
    delete c.idp;
    return JSON.stringify(c);
  })(),
  social_idp: JSON.stringify({
    ...claims,
    idp: "http://github.com/login/oauth/authorize",
  }),
  future_nbf: JSON.stringify({ ...claims, nbf: 1900000001 }),
  duplicate_idp: JSON.stringify(claims).replace('"idp":', '"idp":null,"idp":'),
};
for (const [name, raw] of Object.entries(variants)) {
  const signed = await new CompactSign(Buffer.from(raw))
    .setProtectedHeader(header)
    .sign(privateKey);
  noir += fixture(name + "_fixture", signed);
  noir +=
    "pub fn " +
    name +
    "_payload()->BoundedVec<u8,512>{BoundedVec::from_array(" +
    JSON.stringify(raw) +
    ".as_bytes())}\n";
}
await writeFile(
  new URL(
    "noir/university_auth/src/fixture.nr",
    root,
  ),
  noir,
);
console.log(
  "Generated synthetic university tokens and independently verified core CILogon profile.",
);
