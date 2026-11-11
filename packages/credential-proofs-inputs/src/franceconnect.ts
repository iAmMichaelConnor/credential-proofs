import { publicOidcSources } from "./provider-config.js";
import {
  compactDecrypt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";
import { importVerifiedEs256, type Es256Expected } from "./es256.js";
import { assertOidcJsonProfile } from "./oidc-json.js";
import { decodeJwsJson, selectVerificationJwk } from "./jws.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
export type FranceConnectExpected = Omit<Es256Expected, "issuer"> & {
  environment: "production" | "integration";
  minimumAcr: 2 | 3;
};
export function franceConnectIssuer(
  environment: FranceConnectExpected["environment"],
): string {
  if (environment === "production")
    return publicOidcSources.franceconnect.issuer;
  if (environment === "integration")
    return publicOidcSources.franceconnect_integration.issuer;
  throw Error("unsupported FranceConnect+ environment");
}
export async function decryptFranceConnectJwe(
  token: string,
  privateJwk: JWK,
): Promise<string> {
  if (
    !["RSA-OAEP-256", "ECDH-ES"].includes(privateJwk.alg ?? "") ||
    !privateJwk.d
  )
    throw Error(
      "explicit local recipient private key and supported JWE algorithm required",
    );
  const value = await compactDecrypt(
    token,
    await importJWK(privateJwk, privateJwk.alg),
    {
      keyManagementAlgorithms: [privateJwk.alg!],
      contentEncryptionAlgorithms: ["A256GCM"],
    },
  );
  if (
    value.protectedHeader.cty !== undefined &&
    value.protectedHeader.cty !== "JWT"
  )
    throw Error("JWE content type must be JWT");
  const inner = new TextDecoder("utf-8", { fatal: true }).decode(
    value.plaintext,
  );
  if (inner.split(".").length !== 3)
    throw Error("decrypted content must be original compact JWS");
  return inner;
}
export async function importVerifiedFranceConnect(
  token: string,
  expected: FranceConnectExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  if (expected.minimumAcr !== 2 && expected.minimumAcr !== 3)
    throw Error("invalid FranceConnect+ assurance policy");
  const doc = await importVerifiedEs256(
    token,
    { ...expected, issuer: franceConnectIssuer(expected.environment) },
    jwk,
    { header: 192, payload: 1024, signature: 86 },
    1,
  );
  const body = assertOidcJsonProfile(
    decodeJwsJson(Buffer.from(token.split(".")[1]!, "base64url")),
    1,
    ["acr"],
  );
  const rank = body.acr === "eidas2" ? 2 : body.acr === "eidas3" ? 3 : 0;
  if (rank < expected.minimumAcr)
    throw Error("FranceConnect+ assurance below policy");
  return {
    ...doc,
    audience: boundedBytes(Buffer.from(expected.audience), 128),
    subject: boundedBytes(Buffer.from(expected.subject), 256),
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
    integration: expected.environment === "integration",
    minimum_acr: expected.minimumAcr,
  };
}
export async function importFranceConnectToken(
  token: string,
  expected: FranceConnectExpected,
): Promise<TomlDocument> {
  const header = decodeProtectedHeader(token);
  if (header.alg !== "ES256" || typeof header.kid !== "string")
    throw Error("FranceConnect+ ES256 inner JWS with kid required");
  const response = await fetch(
    franceConnectIssuer(expected.environment) + "/jwks",
    { redirect: "error", signal: AbortSignal.timeout(30000) },
  );
  if (!response.ok) throw Error("FranceConnect+ JWKS HTTP " + response.status);
  const data = (await response.json()) as { keys?: JWK[] };
  return importVerifiedFranceConnect(
    token,
    expected,
    selectVerificationJwk(data.keys, {
      kid: header.kid,
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
    }),
  );
}

export type FranceConnectV2Expected = Omit<Es256Expected, "issuer"> & {
  environment: "production" | "sandbox";
  minimumAcr: 1 | 2 | 3;
};
export function franceConnectV2Issuer(
  environment: FranceConnectV2Expected["environment"],
): string {
  if (environment === "production")
    return publicOidcSources.franceconnect_v2.issuer;
  if (environment === "sandbox")
    return publicOidcSources.franceconnect_v2_sandbox.issuer;
  throw Error("unsupported FranceConnect v2 environment");
}
export async function importVerifiedFranceConnectV2(
  token: string,
  expected: FranceConnectV2Expected,
  jwk: JWK,
): Promise<TomlDocument> {
  if (![1, 2, 3].includes(expected.minimumAcr))
    throw Error("invalid FranceConnect v2 assurance policy");
  const doc = await importVerifiedEs256(
    token,
    { ...expected, issuer: franceConnectV2Issuer(expected.environment) },
    jwk,
    { header: 192, payload: 1024, signature: 86 },
    1,
  );
  const body = assertOidcJsonProfile(
    decodeJwsJson(Buffer.from(token.split(".")[1]!, "base64url")),
    1,
    ["acr"],
  );
  const rank =
    body.acr === "eidas1"
      ? 1
      : body.acr === "eidas2"
        ? 2
        : body.acr === "eidas3"
          ? 3
          : 0;
  if (rank < expected.minimumAcr)
    throw Error("FranceConnect v2 assurance below policy");
  return {
    ...doc,
    audience: boundedBytes(Buffer.from(expected.audience), 128),
    subject: boundedBytes(Buffer.from(expected.subject), 256),
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
    sandbox: expected.environment === "sandbox",
    minimum_acr: expected.minimumAcr,
  };
}
export async function importFranceConnectV2Token(
  token: string,
  expected: FranceConnectV2Expected,
): Promise<TomlDocument> {
  const header = decodeProtectedHeader(token);
  if (header.alg !== "ES256" || typeof header.kid !== "string")
    throw Error("FranceConnect v2 ES256 JWS with kid required");
  const response = await fetch(
    franceConnectV2Issuer(expected.environment) + "/jwks",
    { redirect: "error", signal: AbortSignal.timeout(30000) },
  );
  if (!response.ok)
    throw Error("FranceConnect v2 JWKS HTTP " + response.status);
  const data = (await response.json()) as { keys?: JWK[] };
  return importVerifiedFranceConnectV2(
    token,
    expected,
    selectVerificationJwk(data.keys, {
      kid: header.kid,
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
    }),
  );
}
