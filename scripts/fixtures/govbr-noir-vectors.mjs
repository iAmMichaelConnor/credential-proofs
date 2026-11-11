// Signed synthetic rejection vectors; all private signing material is the public test PEM.
import { readFile, writeFile } from "node:fs/promises";
import { CompactSign, importPKCS8 } from "jose";
import { createSyntheticGovbr } from "credential-proofs-test-builders/govbr";

import { rsaKeyToCircuit } from "credential-proofs-inputs/oidc";

import { boundedBytes, stringifyToml } from "credential-proofs-inputs/toml";

const e = {
  environment: "production",
  audience: "synthetic-client.gov.br",
  subject: "12345678900",
  nonce: "0".repeat(64),
  now: 1900000000,
  minimumLevel: "silver",
};
const x = await createSyntheticGovbr(e);
const key = await importPKCS8(
  await readFile(
    new URL("../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  ),
  "RS256",
);
const raw = Buffer.from(x.token.split(".")[1], "base64url").toString();
const cases = [];
async function save(name, document, reason) {
  await writeFile(
    new URL(`../../target/kat/govbr/${name}.toml`, import.meta.url),
    stringifyToml(document),
  );
  cases.push({ name, reason });
}
function documentFor(token) {
  const d = structuredClone(x.document);
  for (const [i, k] of ["header_b64", "payload_b64", "signature_b64"].entries())
    d.token[k] = boundedBytes(
      Buffer.from(token.split(".")[i]),
      k === "payload_b64" ? 2048 : k === "header_b64" ? 128 : 344,
    );
  return d;
}
async function signed(name, payload, reason) {
  const token = await new CompactSign(Buffer.from(payload))
    .setProtectedHeader({ alg: "RS256", kid: x.jwk.kid, typ: "JWT" })
    .sign(key);
  await save(name, documentFor(token), reason);
}
for (const [field, cap, reason] of [
  ["audience", 128, "wrong OIDC audience"],
  ["subject", 64, "wrong OIDC subject"],
  ["nonce", 64, "wrong OIDC nonce"],
]) {
  const d = structuredClone(x.document);
  d[field] = boundedBytes(Buffer.from("wrong"), cap);
  await save("Reject" + field, d, reason);
}
let d = structuredClone(x.document);
d.now = e.now + 60;
await save("RejectExpiry", d, "OIDC token expired");
d = structuredClone(x.document);
d.staging = true;
await save("RejectEnvironment", d, "wrong OIDC issuer");
await signed(
  "RejectIssuer",
  raw.replace("https://sso.acesso.gov.br/", "https://attacker.example/"),
  "wrong OIDC issuer",
);
await signed(
  "RejectBronze",
  raw.replace('"level":"gold"', '"level":"bronze"'),
  "gov.br assurance below policy",
);
await signed(
  "RejectShadowEscalation",
  raw.replace('"level":"gold"', '"level":"bronze","other":{"level":"gold"}'),
  "gov.br assurance below policy",
);
await signed(
  "RejectDuplicateLevel",
  raw.replace('"level":"gold"', '"level":"bronze","level":"gold"'),
  "duplicate assurance level",
);
await signed(
  "RejectDuplicateSubject",
  raw.replace('"sub":"12345678900"', '"sub":"wrong","sub":"12345678900"'),
  "duplicate OIDC claim",
);
await signed(
  "RejectMissingLevel",
  raw.replace('"level":"gold",', ""),
  "missing or unknown gov.br assurance level",
);
await signed(
  "RejectUnknownLevel",
  raw.replace('"level":"gold"', '"level":"platinum"'),
  "missing or unknown gov.br assurance level",
);
const realKeys = JSON.parse(
  await readFile(
    new URL("../../fixtures/data/public-trust/govbr/jwks.json", import.meta.url),
    "utf8",
  ),
);
d = structuredClone(x.document);
d.trusted_key = rsaKeyToCircuit(realKeys.keys.find((k) => k.kty === "RSA"));
await save("RejectWrongKey", d, "Cannot satisfy constraint");
await writeFile(
  new URL("../../target/kat/govbr/vectors.json", import.meta.url),
  JSON.stringify(
    {
      scope:
        "Synthetic repository key signatures; wrong-key vector uses a live public gov.br RSA key, not private issuer material.",
      cases,
    },
    null,
    2,
  ) + "\n",
);
