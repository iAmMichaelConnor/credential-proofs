// The Microsoft Entra account fixture: the token of
// scripts/fixtures/generate-entra.mjs (exact tenant v2
// issuer, nbf, tid, ver 2.0) signed with the public synthetic RS256 test key,
// with the action hash's hex as the nonce.
import { readFile } from "node:fs/promises";
import {
  array,
  bounded,
  credentials,
  padded,
  repository,
  require,
} from "../account.mjs";
import { NOW, otherKey, segments } from "./rs256.mjs";

const TENANT = "12345678-1234-1234-1234-123456789abc";
const AUDIENCE = "12345678-abcd-abcd-abcd-123456789abc";
const SUBJECT = "tenant-pairwise-subject";

export default async function make({ action }) {
  const { importPKCS8, importSPKI, exportJWK, SignJWT } = require("jose");
  const { importVerifiedEntra, entraIssuer } = await import(
    `credential-proofs-inputs/entra`
  );
  const pem = (name) =>
    readFile(`${repository}fixtures/data/${name}`, "utf8");
  const privateKey = await importPKCS8(
    await pem("synthetic-rs256-private.pem"),
    "RS256",
  );
  const jwk = {
    ...(await exportJWK(
      await importSPKI(await pem("synthetic-rs256-public.pem"), "RS256"),
    )),
    kid: "local-synthetic-entra",
    alg: "RS256",
  };
  const claims = {
    iss: entraIssuer(TENANT),
    aud: AUDIENCE,
    sub: SUBJECT,
    nonce: action,
    tid: TENANT,
    ver: "2.0",
    iat: NOW - 60,
    nbf: NOW - 60,
    exp: NOW + 3600,
    name: "Synthetic Test User",
    preferred_username: "synthetic@example.invalid",
    oid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    aio: "synthetic-opaque-value",
    rh: "0.synthetic",
    uti: "synthetic-uti",
  };
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
    .sign(privateKey);
  const document = await importVerifiedEntra(
    token,
    {
      tenant: TENANT,
      audience: AUDIENCE,
      subject: SUBJECT,
      nonce: action,
      now: NOW,
    },
    jwk,
  );
  const key = document.trusted_key;
  return {
    contract: "EntraAccount",
    summary: `A synthetic Microsoft Entra ID token under the public synthetic RS256 test key in\n//! fixtures/data. It is not a Microsoft login.`,
    now: NOW,
    expiry: claims.exp,
    extra: otherKey(key),
    auth: `    AuthInput {
        policy: AuthPolicy {
            modulus_limbs: ${array(key.modulus_limbs.map(String), "            ")},
            redc_params_limbs: ${array(key.redc_params_limbs.map(String), "            ")},
            tenant: ${padded(Buffer.from(TENANT), 36, "            ")},
            audience: ${bounded(Buffer.from(AUDIENCE), 128, "            ")},
            subject: ${bounded(Buffer.from(SUBJECT), 256, "            ")},
        },
${segments(token, [256, 2048, 344])}
    }`,
    claims,
    library: `${credentials}/src/entra.ts importVerifiedEntra; jose SignJWT (the claims of scripts/generate-entra.mjs)`,
    inputs: [
      `fixtures/data/synthetic-rs256-private.pem`,
      `fixtures/data/synthetic-rs256-public.pem`,
      `${credentials}/src/entra.ts`,
    ],
    moduleInputs: [
      "aztec/use-cases/scripts/fixtures/generators/oidc_account/rs256.mjs",
    ],
    keyProvenance: `Public synthetic RS256 test key committed in fixtures/data; not a Microsoft key. Anyone can sign with it.`,
  };
}
