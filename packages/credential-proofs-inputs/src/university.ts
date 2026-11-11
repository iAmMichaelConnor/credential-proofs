/** Institutional OIDC login. Affiliation freshness is deliberately not inferred. */
import { importJWK, jwtVerify, type JWK } from "jose";
import { rsaKeyToCircuit } from "./oidc.js";
import {
  assertJoseHeaderObject,
  assertStructuredJsonDocument,
} from "./oidc-json.js";
import {
  decodeJwsJson,
  compactJws,
  decodeCanonicalBase64url,
  selectVerificationJwk,
} from "./jws.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
export const UNIVERSITY_BOUNDS = {
  header: 256,
  payload: 2048,
  signature: 344,
} as const;
export const CILOGON = {
  issuer: "https://cilogon.org",
  jwks: "https://cilogon.org/oauth2/certs",
  authorization: "https://cilogon.org/authorize",
} as const;
export type UniversityExpected = {
  mode: "cilogon" | "direct";
  issuer: string;
  audience: string;
  subject: string;
  nonce: string;
  now: number;
  institutionalIdp: string;
};
function validatePolicy(e: UniversityExpected) {
  if (e.mode !== "cilogon" && e.mode !== "direct")
    throw Error("unknown university issuer profile");
  if (!Number.isSafeInteger(e.now) || e.now < 0)
    throw Error("invalid university verifier time");
  for (const [value, max] of [
    [e.issuer, 256],
    [e.audience, 128],
    [e.subject, 256],
    [e.nonce, 64],
  ] as const)
    if (Buffer.byteLength(value) < 1 || Buffer.byteLength(value) > max)
      throw Error("university policy exceeds claim capacity");
  if (Buffer.byteLength(e.institutionalIdp) > 256)
    throw Error("institutional idp exceeds capacity");
  if (e.mode === "direct" && e.issuer === CILOGON.issuer)
    throw Error("CILogon requires institutional idp mode");
  // Direct mode never reads the institutional idp, so the circuit examples require it empty.
  if (e.mode === "direct" && e.institutionalIdp.length > 0)
    throw Error("direct mode requires an empty institutional idp");
  if (
    e.mode === "cilogon" &&
    (e.issuer !== CILOGON.issuer || e.institutionalIdp.length === 0)
  )
    throw Error(
      "CILogon requires fixed issuer and explicit trusted institutional idp",
    );
}
/** JWK provenance is independently enrolled by the caller, never a JWT URL. */
export async function importVerifiedUniversity(
  token: string,
  expected: UniversityExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  validatePolicy(expected);
  const [header, payload, signature] = compactJws(token, UNIVERSITY_BOUNDS);
  const h = assertJoseHeaderObject(
    decodeJwsJson(decodeCanonicalBase64url(header)),
  );
  const raw = assertStructuredJsonDocument(
    decodeJwsJson(decodeCanonicalBase64url(payload)),
  );
  if (
    h.alg !== "RS256" ||
    Object.keys(h).some((k) => !["alg", "typ", "kid"].includes(k)) ||
    (h.typ !== undefined && h.typ !== "JWT") ||
    typeof h.kid !== "string" ||
    h.kid.length === 0 ||
    (jwk.kid !== undefined && h.kid !== jwk.kid)
  )
    throw Error("unsupported university JOSE header or key id");
  if (decodeCanonicalBase64url(signature).length !== 256)
    throw Error("university RS256 signature must be 2048 bits");
  const trusted_key = rsaKeyToCircuit(jwk);
  const { payload: claims } = await jwtVerify(
    token,
    await importJWK(jwk, "RS256"),
    {
      algorithms: ["RS256"],
      issuer: expected.issuer,
      audience: expected.audience,
      subject: expected.subject,
      currentDate: new Date(expected.now * 1000),
      clockTolerance: 0,
    },
  );
  if (typeof claims.aud !== "string" || claims.nonce !== expected.nonce)
    throw Error("wrong university audience/nonce");
  // A signed azp must equal the audience, as in the circuit.
  if (raw.azp !== undefined && raw.azp !== expected.audience)
    throw Error("university azp must match aud");
  if (
    !Number.isSafeInteger(claims.exp) ||
    !Number.isSafeInteger(claims.iat) ||
    claims.iat! > expected.now ||
    (claims.nbf !== undefined && !Number.isSafeInteger(claims.nbf))
  )
    throw Error("invalid university token timestamps");
  if (expected.mode === "cilogon" && raw.idp !== expected.institutionalIdp)
    throw Error("wrong original university idp");
  return {
    token: {
      header_b64: boundedBytes(Buffer.from(header), 256),
      payload_b64: boundedBytes(Buffer.from(payload), 2048),
      signature_b64: boundedBytes(Buffer.from(signature), 344),
    },
    trusted_key,
    policy: {
      issuer: boundedBytes(Buffer.from(expected.issuer), 256),
      audience: boundedBytes(Buffer.from(expected.audience), 128),
      subject: boundedBytes(Buffer.from(expected.subject), 256),
      institutional_idp: boundedBytes(
        Buffer.from(expected.institutionalIdp),
        256,
      ),
    },
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
    now: expected.now,
    brokered: expected.mode === "cilogon",
  };
}
export async function importCilogonToken(
  token: string,
  expected: Omit<UniversityExpected, "mode" | "issuer">,
): Promise<TomlDocument> {
  const [h] = compactJws(token, UNIVERSITY_BOUNDS);
  const header = JSON.parse(decodeJwsJson(decodeCanonicalBase64url(h))) as {
    kid?: string;
    alg?: string;
  };
  if (header.alg !== "RS256" || typeof header.kid !== "string")
    throw Error("expected RS256 CILogon kid");
  const response = await fetch(CILOGON.jwks, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw Error("CILogon JWKS request failed");
  const body = (await response.json()) as { keys?: JWK[] };
  return importVerifiedUniversity(
    token,
    { ...expected, mode: "cilogon", issuer: CILOGON.issuer },
    selectVerificationJwk(body.keys, {
      kid: header.kid,
      kty: "RSA",
      alg: "RS256",
    }),
  );
}
/** Exact released attribute only. Never means current student/staff status. */
export function assertAssertedUniversityAffiliation(
  claims: Record<string, unknown>,
  expected: string,
  style: "cilogon-semicolon" | "camelcase-array" | "snakecase-array",
) {
  if (expected.length === 0 || Buffer.byteLength(expected) > 256)
    throw Error("invalid university affiliation policy");
  if (style === "cilogon-semicolon") {
    if (
      typeof claims.affiliation !== "string" ||
      Buffer.byteLength(claims.affiliation) > 256 ||
      !claims.affiliation.split(";").includes(expected)
    )
      throw Error("missing asserted university affiliation");
  } else if (style === "camelcase-array" || style === "snakecase-array") {
    const values =
      claims[
        style === "camelcase-array"
          ? "eduPersonScopedAffiliation"
          : "eduperson_scoped_affiliation"
      ];
    if (
      !Array.isArray(values) ||
      values.length > 16 ||
      values.some((v) => typeof v !== "string" || Buffer.byteLength(v) > 256) ||
      !values.includes(expected)
    )
      throw Error("missing asserted university affiliation");
  } else throw Error("unknown university affiliation claim profile");
}
