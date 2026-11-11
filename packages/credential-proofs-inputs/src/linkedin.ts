import { assertStructuredJsonDocument } from "./oidc-json.js";
import { assertJoseHeaderProfile, rsaKeyToCircuit } from "./oidc.js";
import { importJWK, jwtVerify, type JWK } from "jose";
import { boundedBytes, type TomlDocument } from "./toml.js";
import { decodeJwsJson, selectVerificationJwk } from "./jws.js";

const ISSUER = "https://www.linkedin.com";
const JWKS = "https://www.linkedin.com/oauth/openid/jwks";
const LIMIT = {
  header: 256,
  payload: 2048,
  signature: 684,
  audience: 256,
  subject: 256,
} as const;

export type LinkedInExpected = {
  audience: string;
  subject: string;
  now: number;
};

function b64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value))
    throw new Error("invalid base64url segment");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value)
    throw new Error("noncanonical base64url segment");
  return bytes;
}

function checkExpected(expected: LinkedInExpected): void {
  if (!Number.isSafeInteger(expected.now) || expected.now < 0)
    throw new Error(
      "expected verifier time must be a nonnegative Unix timestamp",
    );
  for (const [name, value, cap] of [
    ["audience", expected.audience, LIMIT.audience],
    ["subject", expected.subject, LIMIT.subject],
  ] as const) {
    const length = Buffer.byteLength(value, "utf8");
    if (length < 1 || length > cap)
      throw new Error(`expected ${name} must be 1..${cap} UTF-8 bytes`);
  }
}

function envelope(token: string): [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("expected a compact three-part JWT");
  const [header, payload, signature] = parts as [string, string, string];
  if (
    header.length > LIMIT.header ||
    payload.length > LIMIT.payload ||
    signature.length > LIMIT.signature
  )
    throw new Error(
      "JWT exceeds the LinkedIn Noir verifier's segment capacities",
    );
  assertJoseHeaderProfile(decodeJwsJson(b64url(header)), true);
  assertStructuredJsonDocument(decodeJwsJson(b64url(payload)));
  if (b64url(signature).length !== 512)
    throw new Error("RS256 signature must be 512 bytes");
  return [header, payload, signature];
}

export async function importVerifiedLinkedIn(
  token: string,
  expected: LinkedInExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  checkExpected(expected);
  const [header] = envelope(token);
  const protectedHeader = JSON.parse(b64url(header).toString("utf8")) as {
    alg?: string;
    kid?: string;
    typ?: string;
  };
  if (
    protectedHeader.alg !== "RS256" ||
    protectedHeader.typ !== "JWT" ||
    typeof protectedHeader.kid !== "string" ||
    jwk.kid !== protectedHeader.kid
  )
    throw new Error("expected a matching RS256 JWT header with kid");
  if (
    (jwk.alg !== undefined && jwk.alg !== "RS256") ||
    (jwk.use !== undefined && jwk.use !== "sig") ||
    (jwk.key_ops !== undefined && !jwk.key_ops.includes("verify"))
  )
    throw new Error(
      "LinkedIn JWKS key is not authorized for RS256 verification",
    );
  const keyParams = rsaKeyToCircuit(jwk, 4096);
  const key = await importJWK(jwk, "RS256");
  const { payload } = await jwtVerify(token, key, {
    algorithms: ["RS256"],
    issuer: ISSUER,
    audience: expected.audience,
    subject: expected.subject,
    currentDate: new Date(expected.now * 1000),
    clockTolerance: 0,
  });
  if (typeof payload.aud !== "string")
    throw new Error(
      "the LinkedIn Noir verifier supports exactly one string audience",
    );
  if (
    payload.exp === undefined ||
    !Number.isInteger(payload.exp) ||
    payload.exp < 0
  )
    throw new Error("LinkedIn exp must be a u64 timestamp");
  if (
    payload.iat === undefined ||
    !Number.isInteger(payload.iat) ||
    payload.iat < 0 ||
    payload.iat > expected.now
  )
    throw new Error(
      "LinkedIn iat must be an integer no later than verifier time",
    );
  if (
    payload.nbf !== undefined &&
    (!Number.isInteger(payload.nbf) ||
      payload.nbf < 0 ||
      payload.nbf > expected.now)
  )
    throw new Error(
      "LinkedIn nbf must be an integer no later than verifier time",
    );
  if (payload.azp !== undefined && payload.azp !== payload.aud)
    throw new Error("LinkedIn azp must equal aud");
  const parts = token.split(".") as [string, string, string];
  const hb = Buffer.from(parts[0], "ascii"),
    pb = Buffer.from(parts[1], "ascii"),
    sb = Buffer.from(parts[2], "ascii");
  return {
    token: {
      header_b64: boundedBytes(hb, LIMIT.header),
      payload_b64: boundedBytes(pb, LIMIT.payload),
      signature_b64: boundedBytes(sb, LIMIT.signature),
    },
    trusted_key: keyParams,
    audience: boundedBytes(Buffer.from(expected.audience, "utf8"), LIMIT.audience),
    subject: boundedBytes(Buffer.from(expected.subject, "utf8"), LIMIT.subject),
    now: expected.now,
  };
}

export async function importLinkedInToken(
  token: string,
  expected: LinkedInExpected,
): Promise<TomlDocument> {
  checkExpected(expected);
  const url = new URL(JWKS);
  if (url.protocol !== "https:" || url.hostname !== "www.linkedin.com")
    throw new Error("refusing non-LinkedIn JWKS endpoint");
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    redirect: "error",
  });
  if (!response.ok)
    throw new Error(
      `LinkedIn JWKS request failed with HTTP ${response.status}`,
    );
  const jwks = (await response.json()) as { keys?: JWK[] };
  if (!Array.isArray(jwks.keys))
    throw new Error("LinkedIn JWKS response has no keys array");
  const [header] = envelope(token);
  const protectedHeader = JSON.parse(b64url(header).toString("utf8")) as {
    alg?: string;
    kid?: string;
  };
  return importVerifiedLinkedIn(
    token,
    expected,
    selectVerificationJwk(jwks.keys, {
      kid: protectedHeader.kid,
      kty: "RSA",
      alg: "RS256",
    }),
  );
}

export const linkedInIssuer = ISSUER;
