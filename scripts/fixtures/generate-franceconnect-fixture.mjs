import { writeToml } from "credential-proofs-inputs/toml";

import { syntheticP256Jwk, signSyntheticEs256 } from "credential-proofs-test-builders/synthetic-es256";

import { importVerifiedFranceConnect, franceConnectIssuer, importVerifiedFranceConnectV2, franceConnectV2Issuer } from "credential-proofs-inputs/franceconnect";

import { writeFile } from "node:fs/promises";
const nonce = process.argv[2] ?? "0".repeat(64);
if (!/^[0-9a-f]{64}$/.test(nonce)) throw Error("expected64 action hex");
const standard = process.argv[3] === "standard";
const profile = standard ? "franceconnect_v2" : "franceconnect";
const expected = {
  environment: "production",
  minimumAcr: standard ? 1 : 2,
  audience: "synthetic-fcplus-client",
  subject: "synthetic-pairwise-service-subject",
  nonce,
  now: 1900000000,
};
const payload = {
  iss: (standard ? franceConnectV2Issuer : franceConnectIssuer)(
    expected.environment,
  ),
  aud: expected.audience,
  sub: expected.subject,
  nonce,
  iat: 1899999940,
  auth_time: 1899999940,
  exp: 1900000060,
  acr: standard ? "eidas1" : "eidas2",
  amr: ["fc", "pwd"],
};
const jwk = syntheticP256Jwk();
const token = signSyntheticEs256(payload);
await writeToml(
  new URL(
    `../../target/kat/${standard ? "franceconnect_v2" : "franceconnect_v1"}/Prover.toml`,
    import.meta.url,
  ).pathname,
  await (
    standard ? importVerifiedFranceConnectV2 : importVerifiedFranceConnect
  )(token, expected, jwk),
);
await writeFile(
  new URL(`../../fixtures/data/${profile}.synthetic.json`, import.meta.url),
  JSON.stringify(
    {
      provenance:
        "Local synthetic public scalar42, not a FranceConnect-issued credential",
      expected,
      jwk,
      token,
    },
    null,
    2,
  ) + "\n",
);
