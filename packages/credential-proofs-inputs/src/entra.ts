import { importJWK, jwtVerify, type JWK } from "jose";
import {
  assertFlatOidcJson,
  assertJoseHeaderProfile,
  rsaKeyToCircuit,
} from "./oidc.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
import { decodeJwsJson, selectVerificationJwk } from "./jws.js";
export type EntraExpected = {
  tenant: string;
  audience: string;
  subject: string;
  nonce: string;
  now: number;
};
export const ENTRA_BOUNDS = {
  header: 256,
  payload: 2048,
  signature: 344,
} as const;
export function entraIssuer(tenant: string): string {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      tenant,
    )
  )
    throw new Error("tenant must be a canonical lowercase GUID");
  return `https://login.microsoftonline.com/${tenant}/v2.0`;
}
function segments(token: string): [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("expected a compact three-part JWT");
  const result = parts as [string, string, string];
  for (const [i, cap] of [
    ENTRA_BOUNDS.header,
    ENTRA_BOUNDS.payload,
    ENTRA_BOUNDS.signature,
  ].entries()) {
    const value = result[i]!;
    if (
      value.length > cap ||
      !/^[A-Za-z0-9_-]+$/.test(value) ||
      Buffer.from(value, "base64url").toString("base64url") !== value
    )
      throw new Error("JWT exceeds capacity or has noncanonical base64url");
  }
  if (Buffer.from(result[2], "base64url").length !== 256)
    throw new Error("RS256 requires a 2048-bit signature");
  return result;
}
/** The supplied JWK must come from the consumer's authenticated trust policy. */
export async function importVerifiedEntra(
  token: string,
  expected: EntraExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  const issuer = entraIssuer(expected.tenant);
  if (!Number.isSafeInteger(expected.now) || expected.now < 0)
    throw new Error("invalid verifier time");
  for (const [value, cap] of [
    [expected.audience, 128],
    [expected.subject, 256],
    [expected.nonce, 64],
  ] as const)
    if (Buffer.byteLength(value) < 1 || Buffer.byteLength(value) > cap)
      throw new Error("expected claim exceeds circuit bounds");
  const [header, payload, signature] = segments(token);

  assertJoseHeaderProfile(decodeJwsJson(Buffer.from(header, "base64url")));
  const rawClaims = decodeJwsJson(Buffer.from(payload, "base64url"));
  assertFlatOidcJson(rawClaims);
  const parsedRawClaims = JSON.parse(rawClaims) as Record<string, unknown>;
  const key = rsaKeyToCircuit(jwk);
  const { payload: claims, protectedHeader } = await jwtVerify(
    token,
    await importJWK(jwk, "RS256"),
    {
      algorithms: ["RS256"],
      issuer,
      audience: expected.audience,
      subject: expected.subject,
      currentDate: new Date(expected.now * 1000),
      clockTolerance: 0,
    },
  );
  if (
    typeof protectedHeader.kid !== "string" ||
    protectedHeader.kid.length === 0 ||
    (jwk.kid !== undefined && protectedHeader.kid !== jwk.kid)
  )
    throw new Error("wrong Entra signing key id");
  if (claims.tid !== expected.tenant || claims.ver !== "2.0")
    throw new Error("wrong Entra tenant or token version");
  if (claims.nonce !== expected.nonce) throw new Error("wrong Entra nonce");
  if (typeof claims.aud !== "string")
    throw new Error("Entra audience must be a string");
  if (
    parsedRawClaims.azp !== undefined &&
    parsedRawClaims.azp !== parsedRawClaims.aud
  )
    throw new Error("Entra azp must equal aud under the Noir profile");
  if (
    !Number.isSafeInteger(claims.exp) ||
    (claims.nbf !== undefined && !Number.isSafeInteger(claims.nbf))
  )
    throw new Error("invalid token timestamps");
  return {
    now: expected.now,
    tenant: [...Buffer.from(expected.tenant)],
    audience: boundedBytes(Buffer.from(expected.audience), 128),
    subject: boundedBytes(Buffer.from(expected.subject), 256),
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
    token: {
      header_b64: boundedBytes(Buffer.from(header), ENTRA_BOUNDS.header),
      payload_b64: boundedBytes(Buffer.from(payload), ENTRA_BOUNDS.payload),
      signature_b64: boundedBytes(
        Buffer.from(signature),
        ENTRA_BOUNDS.signature,
      ),
    },
    trusted_key: key,
  };
}
export async function importEntraToken(
  token: string,
  expected: EntraExpected,
): Promise<TomlDocument> {
  entraIssuer(expected.tenant);
  const [header] = segments(token);
  const jose = JSON.parse(decodeJwsJson(Buffer.from(header, "base64url"))) as {
    alg?: string;
    kid?: string;
  };
  if (jose.alg !== "RS256" || typeof jose.kid !== "string")
    throw new Error("expected an RS256 header with kid");
  const response = await fetch(
    `https://login.microsoftonline.com/${expected.tenant}/discovery/v2.0/keys`,
    { redirect: "error", headers: { accept: "application/json" } },
  );
  if (!response.ok)
    throw new Error(`Microsoft JWKS failed with HTTP ${response.status}`);
  const jwks = (await response.json()) as {
    keys?: (JWK & { issuer?: string })[];
  };
  const key = selectVerificationJwk(jwks.keys, {
    kid: jose.kid,
    kty: "RSA",
    alg: "RS256",
  });
  if (
    key.issuer !== undefined &&
    key.issuer !== entraIssuer(expected.tenant) &&
    key.issuer !== "https://login.microsoftonline.com/{tenantid}/v2.0"
  )
    throw new Error("JWKS key issuer does not match tenant");
  return importVerifiedEntra(token, expected, key);
}
