/** Shared canonical compact-JWS envelope. Cryptographic trust is caller work. */
export type JwsCapacities = {
  header: number;
  payload: number;
  signature: number;
};
export function decodeCanonicalBase64url(value: string): Buffer {
  const bytes = Buffer.from(value, "base64url");
  if (!/^[A-Za-z0-9_-]+$/.test(value) || bytes.toString("base64url") !== value)
    throw Error("noncanonical base64url");
  return bytes;
}
export function compactJws(
  token: string,
  capacity: JwsCapacities,
): [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3) throw Error("expected compact three-part JWS");
  for (const [i, max] of [
    capacity.header,
    capacity.payload,
    capacity.signature,
  ].entries()) {
    if (parts[i]!.length > max)
      throw Error("JWS exceeds encoded segment capacity");
    decodeCanonicalBase64url(parts[i]!);
  }
  return parts as [string, string, string];
}
/** The key selector of `selectVerificationJwk`. */
export interface JwkSelector {
  kid: unknown;
  kty: "RSA" | "EC";
  crv?: string;
  alg: "RS256" | "ES256";
  requireAlg?: boolean;
}
/**
 * The one JWKS rule of every credential importer: exactly one
 * key has the token's kid and the expected kty (and crv), its alg is absent
 * or the expected one (present when `requireAlg`), its use is absent or
 * "sig", its key_ops is absent or contains "verify", and it is public.
 * The importer then verifies the JWS with it and binds it in the circuit.
 */
export function selectVerificationJwk<
  K extends {
    kid?: string;
    kty?: string;
    crv?: string;
    alg?: string;
    use?: string;
    key_ops?: string[];
    d?: string;
  },
>(keys: K[] | undefined, s: JwkSelector): K {
  if (typeof s.kid !== "string" || s.kid.length === 0)
    throw Error("JWT kid is required");
  if (!Array.isArray(keys)) throw Error("JWKS response has no keys array");
  const matches = keys.filter(
    (k) =>
      k !== null &&
      typeof k === "object" &&
      k.kid === s.kid &&
      k.kty === s.kty &&
      (s.crv === undefined || k.crv === s.crv) &&
      (k.alg === s.alg || (!s.requireAlg && k.alg === undefined)) &&
      (k.use === undefined || k.use === "sig") &&
      (k.key_ops === undefined ||
        (Array.isArray(k.key_ops) && k.key_ops.includes("verify"))) &&
      k.d === undefined,
  );
  if (matches.length !== 1)
    throw Error(
      `JWT kid must match exactly one ${s.alg} verification key in the JWKS`,
    );
  return matches[0]!;
}

/** Decode signed JSON without discarding bytes that the Noir scanners receive. */
export function decodeJwsJson(bytes: Uint8Array): string {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw Error("JWS JSON must not start with a UTF-8 BOM");
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
    bytes,
  );
}
