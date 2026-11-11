// Explicit local test key. This output is synthetic and never a Microsoft login.
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { importPKCS8, importSPKI, exportJWK, SignJWT } from "jose";
import { importVerifiedEntra, entraIssuer } from "credential-proofs-inputs/entra";

import { boundedBytes, stringifyToml } from "credential-proofs-inputs/toml";

const root = fileURLToPath(new URL("../../", import.meta.url));
const expected = {
  tenant: "12345678-1234-1234-1234-123456789abc",
  audience: "12345678-abcd-abcd-abcd-123456789abc",
  subject: "tenant-pairwise-subject",
  nonce: process.argv[2] ?? "synthetic-action-nonce",
  now: 1900000000,
};
const privateKey = await importPKCS8(
  await readFile(
    new URL("../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  ),
  "RS256",
);
const jwk = {
  ...(await exportJWK(
    await importSPKI(
      await readFile(
        new URL("../../fixtures/data/synthetic-rs256-public.pem", import.meta.url),
        "utf8",
      ),
      "RS256",
    ),
  )),
  kid: "local-synthetic-entra",
  alg: "RS256",
};
const token = await new SignJWT({
  iss: entraIssuer(expected.tenant),
  aud: expected.audience,
  sub: expected.subject,
  nonce: expected.nonce,
  tid: expected.tenant,
  ver: "2.0",
  iat: 1899999940,
  nbf: 1899999940,
  exp: 1900003600,
  name: "Synthetic Test User",
  preferred_username: "synthetic@example.invalid",
  oid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  aio: "synthetic-opaque-value",
  rh: "0.synthetic",
  uti: "synthetic-uti",
})
  .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
  .sign(privateKey);
const doc = await importVerifiedEntra(token, expected, jwk);
{
  await writeFile(root + "target/kat/entra/Prover.toml", stringifyToml(doc));
  for (const [name, overrides] of Object.entries({
    WrongIssuer: { iss: "https://login.microsoftonline.com/common/v2.0" },
    WrongAudience: { aud: "wrong-client" },
    WrongNonce: { nonce: "wrong-action" },
    Future: { nbf: 1900000001 },
  })) {
    const claims = {
      ...JSON.parse(
        Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
      ),
      ...overrides,
    };
    const negativeToken = await new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: jwk.kid })
      .sign(privateKey);
    const parts = negativeToken.split(".");
    const negative = structuredClone(doc);
    negative.token = {
      header_b64: boundedBytes(Buffer.from(parts[0]), 256),
      payload_b64: boundedBytes(Buffer.from(parts[1]), 2048),
      signature_b64: boundedBytes(Buffer.from(parts[2]), 344),
    };
    await writeFile(
      root + `target/kat/entra/${name}.toml`,
      stringifyToml(negative),
    );
  }
  await writeFile(
    root + "target/kat/entra/Expired.toml",
    stringifyToml({ ...doc, now: 1900003600 }),
  );
}
console.log(
  "Wrote explicitly synthetic Entra standalone fixtures; nonce",
  expected.nonce,
);
