import { publicOidcSources } from "./provider-config.js";
import { assertJoseHeaderObject, assertOidcJsonProfile } from "./oidc-json.js";
import { decodeJwsJson, selectVerificationJwk } from "./jws.js";
import { readFile } from "node:fs/promises";
import {
  importJWK,
  jwtVerify,
  type JWK,
} from "jose";
import { boundedBytes, type TomlDocument } from "./toml.js";

export type Provider =
  | "google"
  | "apple"
  | "telegram"
  | "kakao"
  | "miargentina"
  | "facebook";

const providerConfig: Record<
  Provider,
  { issuer: string | readonly string[]; jwks: string; circuit: string }
> = {
  miargentina: { ...publicOidcSources.miargentina, circuit: "miargentina" },
  kakao: { ...publicOidcSources.kakao, circuit: "kakao" },
  facebook: { ...publicOidcSources.facebook, circuit: "facebook" },
  google: {
    issuer: ["https://accounts.google.com", "accounts.google.com"],
    jwks: publicOidcSources.google.jwks,
    circuit: "google",
  },
  telegram: {
    ...publicOidcSources.telegram,
    circuit: "telegram",
  },
  apple: {
    ...publicOidcSources.apple,
    circuit: "apple",
  },
};

const MAX = {
  header: 128,
  payload: 1024,
  signature: 344,
  audience: 128,
  subject: 64,
  nonce: 64,
} as const;

export type OidcExpected = {
  audience: string;
  subject: string;
  nonce: string;
  now: number;
};

function subjectCapacity(provider: Provider): number {
  return provider === "facebook" ? 256 : MAX.subject;
}

function checkExpected(expected: OidcExpected, provider: Provider): void {
  if (!Number.isSafeInteger(expected.now) || expected.now < 0)
    throw new Error(
      "expected verifier time must be a nonnegative Unix timestamp",
    );
  const maxSubject = subjectCapacity(provider);
  for (const [name, value, capacity] of [
    ["audience", expected.audience, MAX.audience],
    ["subject", expected.subject, maxSubject],
    ["nonce", expected.nonce, MAX.nonce],
  ] as const) {
    const length = Buffer.byteLength(value, "utf8");
    if (length < 1 || length > capacity)
      throw new Error(`expected ${name} must be 1..${capacity} UTF-8 bytes`);
  }
}

function checkTokenEnvelope(token: string): void {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("expected a compact three-part JWT");
  const [header, payload, signature] = parts as [string, string, string];
  if (
    header.length > MAX.header ||
    payload.length > MAX.payload ||
    signature.length > MAX.signature
  ) {
    throw new Error(
      "JWT exceeds the Noir verifier's encoded segment capacities",
    );
  }
  decodeB64url(header);
  decodeB64url(payload);
  decodeB64url(signature);
}

function decodeB64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value))
    throw new Error("invalid base64url segment");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value)
    throw new Error("noncanonical base64url segment");
  return decoded;
}

function limbArray(value: bigint, count = 18): string[] {
  const mask = (1n << 120n) - 1n;
  const out: string[] = [];
  let rest = value;
  for (let i = 0; i < count; i++) {
    out.push((rest & mask).toString());
    rest >>= 120n;
  }
  if (rest !== 0n)
    throw new Error("RSA key parameter exceeds the 18-limb circuit envelope");
  return out;
}

export function rsaKeyToCircuit(
  jwk: JWK,
  bits: 1024 | 2048 | 4096 = 2048,
): { modulus_limbs: string[]; redc_params_limbs: string[] } {
  if (jwk.kty !== "RSA" || jwk.n === undefined || jwk.e !== "AQAB") {
    throw new Error("only RSA public keys with exponent 65537 are accepted");
  }
  const modulusBytes = decodeB64url(jwk.n);
  if (modulusBytes.length !== bits / 8 || (modulusBytes[0]! & 0x80) === 0) {
    throw new Error(`provider RSA modulus must be exactly ${bits} bits`);
  }
  // The circuit (rsa_signature::assert_rsa_modulus_shape) also requires an odd modulus.
  if ((modulusBytes[modulusBytes.length - 1]! & 1) === 0)
    throw new Error("provider RSA modulus must be odd");
  const modulus = BigInt(`0x${modulusBytes.toString("hex")}`);
  const barrettRedc = (1n << BigInt(2 * bits + 6)) / modulus;
  return {
    modulus_limbs: limbArray(modulus, Math.ceil(bits / 120)),
    redc_params_limbs: limbArray(barrettRedc, Math.ceil(bits / 120)),
  };
}

function tomlForToken(
  token: string,
  key: { modulus_limbs: string[]; redc_params_limbs: string[] },
  expected: OidcExpected,
  subjectCap: number,
): TomlDocument {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("expected a compact three-part JWT");
  const [header, payload, signature] = parts as [string, string, string];
  const headerBytes = decodeB64url(header);
  const payloadBytes = decodeB64url(payload);
  const signatureBytes = decodeB64url(signature);
  if (signatureBytes.length !== 256)
    throw new Error("RS256 signature must be 256 bytes");
  return {
    now: expected.now,
    token: {
      header_b64: boundedBytes(Buffer.from(header, "ascii"), MAX.header),
      payload_b64: boundedBytes(Buffer.from(payload, "ascii"), MAX.payload),
      signature_b64: boundedBytes(
        Buffer.from(signature, "ascii"),
        MAX.signature,
      ),
    },
    trusted_key: key,
    audience: boundedBytes(
      Buffer.from(expected.audience, "utf8"),
      MAX.audience,
    ),
    subject: boundedBytes(Buffer.from(expected.subject, "utf8"), subjectCap),
    nonce: boundedBytes(Buffer.from(expected.nonce, "utf8"), MAX.nonce),
  };
}

/** Match the shared Noir flat JSON profile before producing witness inputs. */
export function assertFlatOidcJson(raw: string): void {
  assertOidcJsonProfile(raw, 0);
}

/** Match the default Noir JWS header profile before handing the original token to the circuit. */
export function assertJoseHeaderProfile(
  raw: string,
  requireTyp = false,
): Record<string, unknown> {
  const header = assertJoseHeaderObject(raw);
  for (const [name, value] of Object.entries(header)) {
    if (name !== "alg" && name !== "typ" && name !== "kid") {
      throw new Error(`unsupported JWS header field: ${name}`);
    }
    if (typeof value !== "string")
      throw new Error(`JWS header field ${name} must be a string`);
  }
  if (header.alg !== "RS256") throw new Error("JWS alg must be RS256");
  if (header.typ !== undefined && header.typ !== "JWT")
    throw new Error("JWS typ must be JWT when present");
  if (requireTyp && header.typ !== "JWT")
    throw new Error("JWS typ must be JWT");
  if (typeof header.kid !== "string" || header.kid.length === 0)
    throw new Error("JWS kid is required");
  return header;
}

export async function importVerifiedOidc(
  provider: Provider,
  token: string,
  expected: OidcExpected,
  jwk: JWK,
): Promise<TomlDocument> {
  checkExpected(expected, provider);
  checkTokenEnvelope(token);
  const [headerSegment, payloadSegment] = token.split(".") as [
    string,
    string,
    string,
  ];
  assertJoseHeaderProfile(decodeJwsJson(decodeB64url(headerSegment)));
  const rawPayload = decodeJwsJson(decodeB64url(payloadSegment));
  const rawClaims = assertOidcJsonProfile(rawPayload, 0);
  const config = providerConfig[provider];
  const key = await importJWK(jwk, "RS256");
  const { payload, protectedHeader } = await jwtVerify(token, key, {
    algorithms: ["RS256"],
    issuer: config.issuer as string | string[],
    audience: expected.audience,
    subject: expected.subject,
    currentDate: new Date(expected.now * 1000),
    clockTolerance: 0,
  });
  if (
    protectedHeader.kid === undefined ||
    protectedHeader.alg !== "RS256" ||
    (jwk.kid !== undefined && protectedHeader.kid !== jwk.kid)
  ) {
    throw new Error("JWT must identify its RS256 provider key with kid");
  }
  if (payload.nonce !== expected.nonce)
    throw new Error("OIDC nonce does not match the expected login session");
  if (typeof payload.aud !== "string")
    throw new Error("the Noir OIDC input supports exactly one string audience");
  if (rawClaims.azp !== undefined && rawClaims.azp !== rawClaims.aud)
    throw new Error("OIDC azp must equal aud under the Noir profile");
  if (payload.exp === undefined || !Number.isSafeInteger(payload.exp))
    throw new Error("OIDC exp must be an integer timestamp");
  if (payload.nbf !== undefined && !Number.isSafeInteger(payload.nbf))
    throw new Error("OIDC nbf must be an integer timestamp");
  return tomlForToken(
    token,
    rsaKeyToCircuit(jwk),
    expected,
    subjectCapacity(provider),
  );
}

export async function importProviderToken(
  provider: Provider,
  token: string,
  expected: OidcExpected,
): Promise<TomlDocument> {
  checkExpected(expected, provider);
  checkTokenEnvelope(token);
  const config = providerConfig[provider];
  const url = new URL(config.jwks);
  if (
    url.protocol !== "https:" ||
    ![
      "www.googleapis.com",
      "appleid.apple.com",
      "oauth.telegram.org",
      "kauth.kakao.com",
      "www.facebook.com",
      "id.argentina.gob.ar",
    ].includes(url.hostname)
  ) {
    throw new Error("refusing non-provider JWKS endpoint");
  }
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    redirect: "error",
  });
  if (!response.ok)
    throw new Error(
      `provider JWKS request failed with HTTP ${response.status}`,
    );
  const jwks = (await response.json()) as { keys?: JWK[] };
  if (!Array.isArray(jwks.keys))
    throw new Error("provider JWKS response has no keys array");
  const protectedHeader = JSON.parse(
    decodeJwsJson(decodeB64url(token.split(".")[0] ?? "")),
  ) as { kid?: string; alg?: string };
  if (
    protectedHeader.alg !== "RS256" ||
    typeof protectedHeader.kid !== "string"
  ) {
    throw new Error("expected an RS256 JWT header with kid");
  }
  const jwk = selectVerificationJwk(jwks.keys, {
    kid: protectedHeader.kid,
    kty: "RSA",
    alg: "RS256",
  });
  return importVerifiedOidc(provider, token, expected, jwk);
}

/** Emit the nested AuthInput layout used by aztec/use-cases/account-authorisation/facebook. */
export async function importFacebookAccountToken(
  token: string,
  expected: OidcExpected,
): Promise<TomlDocument> {
  const document = await importProviderToken("facebook", token, expected);
  return facebookAccountInput(document, expected);
}

export function facebookAccountInput(
  document: TomlDocument,
  expected: OidcExpected,
): TomlDocument {
  const key = document.trusted_key as TomlDocument;
  const segments = document.token as TomlDocument;
  const header = segments.header_b64 as { len: number; storage: number[] };
  const payload = segments.payload_b64 as { len: number; storage: number[] };
  const signature = segments.signature_b64 as {
    len: number;
    storage: number[];
  };
  return {
    policy: {
      modulus_limbs: key.modulus_limbs as string[],
      redc_params_limbs: key.redc_params_limbs as string[],
      audience: boundedBytes(Buffer.from(expected.audience, "utf8"), 128),
      subject: boundedBytes(Buffer.from(expected.subject, "utf8"), 256),
    },
    header_b64: header.storage,
    header_b64_len: header.len,
    payload_b64: payload.storage,
    payload_b64_len: payload.len,
    signature_b64: signature.storage,
    signature_b64_len: signature.len,
  };
}

export async function readTokenFile(path: string): Promise<string> {
  const token = (await readFile(path, "utf8")).trim();
  if (token.length === 0 || token.includes("\n"))
    throw new Error("token file must contain one compact JWT line");
  return token;
}
