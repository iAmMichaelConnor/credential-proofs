import { publicOidcSources } from "./provider-config.js";
import { decodeProtectedHeader, type JWK } from "jose";
import { importVerifiedEs256, type Es256Expected } from "./es256.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
import { selectVerificationJwk } from "./jws.js";
export const LINE_ISSUER: string = publicOidcSources.line.issuer;
export const LINE_JWKS: string = publicOidcSources.line.jwks;
export type LineExpected = Omit<Es256Expected, "issuer">;
export async function importVerifiedLine(
  token: string,
  expected: LineExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  if (!/^[0-9]{1,32}$/.test(expected.audience))
    throw new Error("LINE channel ID must be decimal and at most 32 bytes");
  const document = await importVerifiedEs256(
    token,
    { ...expected, issuer: LINE_ISSUER },
    jwk,
    { header: 192, payload: 1024, signature: 86 },
    1,
  );
  return {
    ...document,
    channel_id: boundedBytes(Buffer.from(expected.audience), 32),
    subject: boundedBytes(Buffer.from(expected.subject), 256),
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
  };
}
export async function importLineToken(
  token: string,
  expected: LineExpected,
): Promise<TomlDocument> {
  const header = decodeProtectedHeader(token);
  if (header.alg !== "ES256" || typeof header.kid !== "string")
    throw new Error(
      "LINE native ES256 token with kid required; HS256 web login unsupported",
    );
  const response = await fetch(LINE_JWKS, {
    redirect: "error",
    headers: { accept: "application/json" },
  });
  if (!response.ok) throw new Error(`LINE JWKS HTTP ${response.status}`);
  const jwks = (await response.json()) as { keys?: JWK[] };
  // LINE publishes alg on its keys; the importer keeps requiring it.
  return importVerifiedLine(
    token,
    expected,
    selectVerificationJwk(jwks.keys, {
      kid: header.kid,
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
      requireAlg: true,
    }),
  );
}
