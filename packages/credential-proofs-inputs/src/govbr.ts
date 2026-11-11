import {
  importJWK,
  jwtVerify,
  type JWK,
} from "jose";
import { rsaKeyToCircuit } from "./oidc.js";
import { assertJoseHeaderObject, assertOidcJsonProfile } from "./oidc-json.js";
import { decodeJwsJson, selectVerificationJwk } from "./jws.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
export type AssuranceLevel = "bronze" | "silver" | "gold";
export type GovbrExpected = {
  environment: "production" | "staging";
  audience: string;
  subject: string;
  nonce: string;
  now: number;
  minimumLevel: AssuranceLevel;
};
export const GOVBR_BOUNDS = {
  header: 128,
  payload: 2048,
  signature: 344,
} as const;
export const assuranceRank = (level: unknown): number =>
  level === "bronze" ? 1 : level === "silver" ? 2 : level === "gold" ? 3 : 0;
export const govbrIssuer = (
  environment: GovbrExpected["environment"],
): string => {
  if (environment !== "production" && environment !== "staging")
    throw Error("unknown gov.br environment");
  return environment === "production"
    ? "https://sso.acesso.gov.br/"
    : "https://sso.staging.acesso.gov.br/";
};
function segments(token: string): [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3) throw Error("expected compact three-part JWT");
  for (const [i, cap] of [
    GOVBR_BOUNDS.header,
    GOVBR_BOUNDS.payload,
    GOVBR_BOUNDS.signature,
  ].entries()) {
    const value = parts[i]!;
    if (
      value.length > cap ||
      !/^[A-Za-z0-9_-]+$/.test(value) ||
      Buffer.from(value, "base64url").toString("base64url") !== value
    )
      throw Error("JWT exceeds capacity or has noncanonical base64url");
  }
  if (Buffer.from(parts[2]!, "base64url").length !== 256)
    throw Error("RS256 signature must be 2048 bits");
  return parts as [string, string, string];
}
/** Explicit JWK must be authenticated by the consumer's enrolled trust policy. */
export async function importVerifiedGovbr(
  token: string,
  expected: GovbrExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  const issuer = govbrIssuer(expected.environment);
  if (
    !Number.isSafeInteger(expected.now) ||
    expected.now < 0 ||
    assuranceRank(expected.minimumLevel) === 0
  )
    throw Error("invalid gov.br time or assurance policy");
  for (const [value, cap] of [
    [expected.audience, 128],
    [expected.subject, 64],
    [expected.nonce, 64],
  ] as const)
    if (Buffer.byteLength(value) < 1 || Buffer.byteLength(value) > cap)
      throw Error("expected gov.br claim exceeds capacity");
  const [header, payload, signature] = segments(token);
  const jose = assertJoseHeaderObject(
    decodeJwsJson(Buffer.from(header, "base64url")),
  );
  const rawClaims = assertOidcJsonProfile(
    decodeJwsJson(Buffer.from(payload, "base64url")),
    2,
  );
  if (
    Object.keys(jose).some((key) => !["alg", "kid", "typ"].includes(key)) ||
    jose.alg !== "RS256" ||
    typeof jose.kid !== "string" ||
    jose.kid.length === 0 ||
    (jose.typ !== undefined && jose.typ !== "JWT") ||
    (jwk.kid !== undefined && jose.kid !== jwk.kid)
  )
    throw Error("unsupported gov.br JOSE header or key id");
  const trusted_key = rsaKeyToCircuit(jwk);
  const { payload: claims } = await jwtVerify(
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
  if (claims.nonce !== expected.nonce) throw Error("wrong gov.br nonce");
  if (typeof claims.aud !== "string")
    throw Error("gov.br audience must be one string");
  if (
    !Number.isSafeInteger(claims.exp) ||
    (claims.nbf !== undefined && !Number.isSafeInteger(claims.nbf))
  )
    throw Error("invalid gov.br timestamps");
  const info = rawClaims.reliability_info as
    | Record<string, unknown>
    | undefined;
  const level = assuranceRank(info?.level);
  if (level === 0) throw Error("missing or unknown gov.br assurance level");
  if (level < assuranceRank(expected.minimumLevel))
    throw Error("gov.br assurance below policy");
  return {
    token: {
      header_b64: boundedBytes(Buffer.from(header), 128),
      payload_b64: boundedBytes(Buffer.from(payload), 2048),
      signature_b64: boundedBytes(Buffer.from(signature), 344),
    },
    trusted_key,
    audience: boundedBytes(Buffer.from(expected.audience), 128),
    subject: boundedBytes(Buffer.from(expected.subject), 64),
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
    now: expected.now,
    staging: expected.environment === "staging",
    minimum_level: assuranceRank(expected.minimumLevel),
  };
}
export async function importGovbrToken(
  token: string,
  expected: GovbrExpected,
): Promise<TomlDocument> {
  const [header] = segments(token);
  const h = JSON.parse(Buffer.from(header, "base64url").toString()) as {
    kid?: string;
    alg?: string;
  };
  if (h.alg !== "RS256" || typeof h.kid !== "string")
    throw Error("expected RS256 provider key id");
  const response = await fetch(`${govbrIssuer(expected.environment)}jwk`, {
    redirect: "error",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw Error(`gov.br JWKS HTTP ${response.status}`);
  const jwks = (await response.json()) as { keys?: JWK[] };
  const key = selectVerificationJwk(jwks.keys, {
    kid: h.kid,
    kty: "RSA",
    alg: "RS256",
  });
  return importVerifiedGovbr(token, expected, key);
}
