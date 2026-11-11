import { decodeJwsJson, decodeCanonicalBase64url as decode } from "./jws.js";
import { importJWK, jwtVerify, type JWK } from "jose";
import { boundedBytes, type TomlDocument } from "./toml.js";
import {
  assertJoseHeaderObject,
  assertOidcJsonProfile,
  assertStructuredJsonDocument,
  type OidcJsonProfile,
} from "./oidc-json.js";

export type Es256Expected = {
  issuer: string;
  audience: string;
  subject: string;
  nonce: string;
  now: number;
};
export type Es256Capacities = {
  header: number;
  payload: number;
  signature: number;
};
const defaults: Es256Capacities = { header: 64, payload: 128, signature: 86 };
function jsonProfile(
  value: Buffer,
  profile: OidcJsonProfile = 0,
): Record<string, unknown> {
  const text = decodeJwsJson(value);
  return assertOidcJsonProfile(text, profile);
}

/** The caller supplies an authenticated issuer JWK. This never fetches a token-selected URL.
 * Expected identity/context must also be bound by the consuming circuit's policy.
 */
export async function importVerifiedEs256(
  token: string,
  expected: Es256Expected,
  jwk: JWK,
  capacity: Es256Capacities = defaults,
  profile: OidcJsonProfile = 0,
): Promise<TomlDocument> {
  return importEs256(token, expected, jwk, capacity, profile);
}
/** Structured signed payload profile. The consumer binds additional root claims;
 * signature and standard single-audience identity/time checks remain shared. */
export async function importVerifiedEs256Document(
  token: string,
  expected: Es256Expected,
  jwk: JWK,
  capacity: Es256Capacities,
): Promise<TomlDocument> {
  return importEs256(token, expected, jwk, capacity, "document");
}
async function importEs256(
  token: string,
  expected: Es256Expected,
  jwk: JWK,
  capacity: Es256Capacities,
  profile: OidcJsonProfile | "document",
): Promise<TomlDocument> {
  if (
    !Number.isSafeInteger(expected.now) ||
    expected.now < 0 ||
    !expected.nonce ||
    !expected.subject
  )
    throw new Error("invalid ES256 verifier policy");
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    !jwk.x ||
    !jwk.y ||
    (jwk.alg !== undefined && jwk.alg !== "ES256") ||
    (jwk.use !== undefined && jwk.use !== "sig") ||
    jwk.d !== undefined
  )
    throw new Error("expected an authenticated ES256 P-256 public key");
  const x = decode(jwk.x),
    y = decode(jwk.y);
  if (x.length !== 32 || y.length !== 32)
    throw new Error("P-256 coordinates must be 32 bytes");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("expected a compact JWT");
  const [h, p, s] = parts as [string, string, string];
  // The document profile is the circuit's structured document.
  const header = assertJoseHeaderObject(decodeJwsJson(decode(h))),
    payload =
      profile === "document"
        ? assertStructuredJsonDocument(decodeJwsJson(decode(p)))
        : jsonProfile(decode(p), profile);
  if (
    header.alg !== "ES256" ||
    Object.keys(header).some((k) => !["alg", "typ", "kid"].includes(k)) ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    (header.kid !== undefined && typeof header.kid !== "string") ||
    (jwk.kid !== undefined && header.kid !== jwk.kid)
  )
    throw new Error("unsupported ES256 JOSE header");
  if (decode(s).length !== 64)
    throw new Error("ES256 signature must be raw r||s");
  // Only the claims the circuit copies are capped at 256 bytes.
  for (const name of ["iss", "aud", "sub", "nonce", "azp"]) {
    const value = payload[name];
    if (typeof value === "string" && Buffer.byteLength(value) > 256)
      throw new Error(`claim ${name} exceeds the Noir profile`);
  }
  for (const name of ["exp", "nbf", "iat"]) {
    const value = payload[name];
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) || (value as number) < 0)
    )
      throw new Error("numeric claim exceeds the Noir profile");
  }
  if (
    typeof payload.aud !== "string" ||
    payload.nonce !== expected.nonce ||
    (payload.azp !== undefined && payload.azp !== payload.aud) ||
    !Number.isSafeInteger(payload.exp) ||
    (payload.nbf !== undefined && !Number.isSafeInteger(payload.nbf))
  )
    throw new Error("invalid ES256 claims");
  await jwtVerify(token, await importJWK(jwk, "ES256"), {
    algorithms: ["ES256"],
    issuer: expected.issuer,
    audience: expected.audience,
    subject: expected.subject,
    currentDate: new Date(expected.now * 1000),
    clockTolerance: 0,
  });
  return {
    now: expected.now,
    key: { public_key_x: [...x], public_key_y: [...y] },
    token: {
      header_b64: boundedBytes(Buffer.from(h), capacity.header),
      payload_b64: boundedBytes(Buffer.from(p), capacity.payload),
      signature_b64: boundedBytes(Buffer.from(s), capacity.signature),
    },
  };
}
