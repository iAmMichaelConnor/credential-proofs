// Locally signed complete JWS vectors; never provider-issued credentials.
import { readFile, writeFile } from "node:fs/promises";
import { signSyntheticEs256Raw } from "credential-proofs-test-builders/synthetic-es256";

import { importVerifiedFranceConnect, importVerifiedFranceConnectV2 } from "credential-proofs-inputs/franceconnect";

import { boundedBytes, stringifyToml } from "credential-proofs-inputs/toml";

for (const name of ["franceconnect", "franceconnect_v2"]) {
  const kat = name === "franceconnect" ? "franceconnect_v1" : name;
  const f = JSON.parse(
    await readFile(
      new URL(`../../fixtures/data/${name}.synthetic.json`, import.meta.url),
    ),
  );
  const raw = Buffer.from(f.token.split(".")[1], "base64url").toString();
  const base = await (
    name === "franceconnect"
      ? importVerifiedFranceConnect
      : importVerifiedFranceConnectV2
  )(f.token, f.expected, f.jwk);
  const cases = [];
  async function save(id, d, reason) {
    await writeFile(
      new URL(`../../target/kat/${kat}/${id}.toml`, import.meta.url),
      stringifyToml(d),
    );
    cases.push({ name: id, reason });
  }
  async function signed(id, payload, reason) {
    const d = structuredClone(base);
    const parts = signSyntheticEs256Raw(payload).split(".");
    for (const [i, k] of [
      "header_b64",
      "payload_b64",
      "signature_b64",
    ].entries())
      d.token[k] = boundedBytes(Buffer.from(parts[i]), [192, 1024, 86][i]);
    await save(id, d, reason);
  }
  await signed(
    "RejectIssuer",
    raw.replace(/"iss":"[^"]+"/, '"iss":"https://attacker.example"'),
    "wrong OIDC issuer",
  );
  await signed(
    "RejectDuplicateAcr",
    raw.replace(/"acr":"[^"]+"/, '"acr":"eidas3","acr":"eidas1"'),
    "duplicate",
  );
  await signed(
    "RejectUnknownAcr",
    raw.replace(/"acr":"[^"]+"/, '"acr":"unknown"'),
    "assurance",
  );
  await signed(
    "RejectMissingAcr",
    raw.replace(/"acr":"[^"]+",/, ""),
    "missing",
  );
  if (name === "franceconnect")
    await signed(
      "RejectLowAcr",
      raw.replace('"acr":"eidas2"', '"acr":"eidas1"'),
      "assurance",
    );
  for (const [field, cap, reason] of [
    ["audience", 128, "wrong OIDC audience"],
    ["subject", 256, "wrong OIDC subject"],
    ["nonce", 64, "wrong OIDC nonce"],
  ]) {
    const d = structuredClone(base);
    d[field] = boundedBytes(Buffer.from("wrong"), cap);
    await save("Reject" + field, d, reason);
  }
  const d = structuredClone(base);
  d.now = 1900000060;
  await save("RejectExpiry", d, "OIDC token expired");
  await writeFile(
    new URL(`../../target/kat/${kat}/vectors.json`, import.meta.url),
    JSON.stringify(
      { scope: "Local synthetic P256 scalar42 complete compact JWS", cases },
      null,
      2,
    ) + "\n",
  );
}
