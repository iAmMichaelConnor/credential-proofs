/** Singpass FAPI inner JWS only. JWE decryption never replaces issuer verification. */
import {
  decodeJwsJson,
  compactJws,
  decodeCanonicalBase64url,
  selectVerificationJwk,
} from "./jws.js";
import { assertStructuredJsonDocument } from "./oidc-json.js";
import { importVerifiedEs256Document, type Es256Expected } from "./es256.js";
import { boundedBytes, type TomlDocument } from "./toml.js";
import { compactDecrypt, importJWK, type JWK } from "jose";
export const SINGPASS_BOUNDS = {
  header: 256,
  payload: 1024,
  signature: 86,
} as const;
export const SINGPASS = {
  production: {
    issuer: "https://id.singpass.gov.sg/fapi",
    jwks: "https://id.singpass.gov.sg/.well-known/keys",
  },
  staging: {
    issuer: "https://stg-id.singpass.gov.sg/fapi",
    jwks: "https://stg-id.singpass.gov.sg/.well-known/keys",
  },
} as const;
export type SingpassExpected = Omit<Es256Expected, "issuer"> & {
  environment: "production" | "staging";
  minimumAssurance: 1 | 2 | 3;
};
export async function importVerifiedSingpass(
  token: string,
  expected: SingpassExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  if (
    !["production", "staging"].includes(expected.environment) ||
    ![1, 2, 3].includes(expected.minimumAssurance) ||
    (expected.environment === "production" && expected.minimumAssurance < 2)
  )
    throw Error("invalid Singpass trust profile");
  if (
    Buffer.byteLength(expected.audience) < 1 ||
    Buffer.byteLength(expected.audience) > 128 ||
    Buffer.byteLength(expected.subject) > 256 ||
    Buffer.byteLength(expected.nonce) > 64
  )
    throw Error("Singpass policy exceeds capacity");
  const raw = assertStructuredJsonDocument(
    decodeJwsJson(
      decodeCanonicalBase64url(compactJws(token, SINGPASS_BOUNDS)[1]),
    ),
  );
  if (raw.sub_type !== "user" || Object.hasOwn(raw, "act"))
    throw Error("unsupported Singpass subject or delegated actor");
  if (!Number.isSafeInteger(raw.iat) || (raw.iat as number) > expected.now)
    throw Error("invalid Singpass issued time");
  if (typeof raw.acr !== "string") throw Error("Singpass acr must be a string");
  const assurance =
    [
      "urn:singpass:authentication:loa:1",
      "urn:singpass:authentication:loa:2",
      "urn:singpass:authentication:loa:3",
    ].indexOf(raw.acr) + 1;
  if (assurance < expected.minimumAssurance)
    throw Error("insufficient Singpass assurance");
  const result = await importVerifiedEs256Document(
    token,
    { ...expected, issuer: SINGPASS[expected.environment].issuer },
    jwk,
    SINGPASS_BOUNDS,
  );
  return {
    ...result,
    policy: {
      audience: boundedBytes(Buffer.from(expected.audience), 128),
      subject: boundedBytes(Buffer.from(expected.subject), 256),
      environment: expected.environment === "production" ? 0 : 1,
      minimum_assurance: expected.minimumAssurance,
    },
    nonce: boundedBytes(Buffer.from(expected.nonce), 64),
  };
}
export async function importSingpassToken(
  token: string,
  expected: SingpassExpected,
): Promise<TomlDocument> {
  const [h] = compactJws(token, SINGPASS_BOUNDS);
  const header = JSON.parse(decodeJwsJson(decodeCanonicalBase64url(h))) as {
    kid?: string;
    alg?: string;
  };
  if (header.alg !== "ES256" || typeof header.kid !== "string")
    throw Error("expected Singpass ES256 kid");
  const response = await fetch(SINGPASS[expected.environment].jwks, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw Error("Singpass JWKS request failed");
  const body = (await response.json()) as { keys?: JWK[] };
  return importVerifiedSingpass(
    token,
    expected,
    selectVerificationJwk(body.keys, {
      kid: header.kid,
      kty: "EC",
      crv: "P-256",
      alg: "ES256",
    }),
  );
}

/** Decrypt only the relying-party transport. The returned untouched inner JWS
 * still requires importVerifiedSingpass/importSingpassToken issuer verification. */
export async function decryptSingpassJwe(
  token: string,
  recipientJwk: JWK,
): Promise<string> {
  const result = await compactDecrypt(
    token,
    await importJWK(recipientJwk, "ECDH-ES+A256KW"),
    {
      keyManagementAlgorithms: [
        "ECDH-ES+A256KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A128KW",
      ],
      contentEncryptionAlgorithms: ["A256CBC-HS512"],
    },
  );
  if (result.protectedHeader.cty !== "JWT") throw Error("JWE cty must be JWT");
  return new TextDecoder("utf-8", { fatal: true }).decode(result.plaintext);
}
