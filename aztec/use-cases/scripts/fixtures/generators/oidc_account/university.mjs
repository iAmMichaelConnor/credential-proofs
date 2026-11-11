// The university (CILogon) account fixture: the local synthetic CILogon
// token in fixtures/material/university/local-test with
// its nonce replaced by the action hex, re-signed with the public synthetic
// RS256 test key.
import { readFile } from "node:fs/promises";
import {
  array,
  bounded,
  credentials,
  padded,
  repository,
  require,
} from "../account.mjs";
import { otherKey } from "./rs256.mjs";

const material = `fixtures/material/university/local-test`;

export default async function ({ action }) {
  const { SignJWT, importPKCS8 } = require("jose");
  const { rsaKeyToCircuit } = await import(
    `credential-proofs-inputs/oidc`
  );
  const read = (path) => readFile(`${repository}${path}`, "utf8");
  const original = (await read(`${material}/id-token.txt`)).trim();
  const jwk = JSON.parse(await read(`${material}/issuer-key.json`));
  const expected = JSON.parse(await read(`${material}/policy.json`));
  const key = rsaKeyToCircuit(jwk);
  const claims = JSON.parse(
    Buffer.from(original.split(".")[1], "base64url").toString("utf8"),
  );
  claims.nonce = action;
  const privateKey = await importPKCS8(
    await read(`fixtures/data/synthetic-rs256-private.pem`),
    "RS256",
  );
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
    .sign(privateKey);
  const parts = token.split(".");
  const segment = (name, i, capacity) => {
    const bytes = Buffer.from(parts[i], "ascii");
    return `        ${name}: ${padded(bytes, capacity, "        ")},\n        ${name}_len: ${bytes.length},`;
  };
  return {
    contract: "UniversityAccount",
    summary: `A synthetic CILogon ID token (local material/university/local-test claims) under\n//! the public synthetic RS256 test key in fixtures/data. Never CILogon-issued.`,
    now: expected.now,
    expiry: claims.exp,
    extra: otherKey(key),
    auth: `    AuthInput {
        policy: AuthPolicy {
            modulus_limbs: ${array(key.modulus_limbs.map(String), "            ")},
            redc_params_limbs: ${array(key.redc_params_limbs.map(String), "            ")},
            audience: ${bounded(Buffer.from(expected.audience), 128, "            ")},
            subject: ${bounded(Buffer.from(expected.subject), 256, "            ")},
            institutional_idp: ${bounded(Buffer.from(expected.institutionalIdp), 256, "            ")},
        },
${segment("header_b64", 0, 256)}
${segment("payload_b64", 1, 2048)}
${segment("signature_b64", 2, 344)}
    }`,
    claims,
    library: `${credentials}/dist/src/oidc.js rsaKeyToCircuit; jose SignJWT (RS256)`,
    inputs: [
      `${material}/id-token.txt`,
      `${material}/issuer-key.json`,
      `${material}/policy.json`,
      `fixtures/data/synthetic-rs256-private.pem`,
      `${credentials}/src/oidc.ts`,
    ],
    moduleInputs: [
      "aztec/use-cases/scripts/fixtures/generators/oidc_account/rs256.mjs",
    ],
    keyProvenance: `Public synthetic RS256 test key committed in fixtures/data; not a CILogon key. Anyone can sign with it.`,
  };
}
