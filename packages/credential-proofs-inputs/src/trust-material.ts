/** Public-key provenance only. Never grants trust to token-selected URLs. */
import { createHash, createPublicKey } from "node:crypto";
import type { JWK } from "jose";
export const sha256 = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");
export type PublicTrustSource = {
  provider: string;
  url: string;
  issuer: string;
  purpose: string;
  rotation: string;
};
export function describePublicJwks(
  raw: string,
  source: PublicTrustSource,
  fetchedAt: string,
) {
  const body = JSON.parse(raw) as { keys?: JWK[] };
  if (!Array.isArray(body.keys) || body.keys.length === 0)
    throw Error("JWKS must contain public keys");
  const keys = body.keys.map((key) => {
    if (key.d !== undefined || key.k !== undefined)
      throw Error("private/secret key is not public provenance");
    const publicKey = createPublicKey({ key: key as never, format: "jwk" });
    return {
      kid: key.kid ?? null,
      kty: key.kty,
      alg: key.alg ?? null,
      use: key.use ?? null,
      spkiSha256: sha256(publicKey.export({ type: "spki", format: "der" })),
      asymmetricKeyType: publicKey.asymmetricKeyType,
      modulusLength: publicKey.asymmetricKeyDetails?.modulusLength ?? null,
    };
  });
  return {
    schemaVersion: 1,
    kind: "public-jwks",
    ...source,
    fetchedAt,
    responseSha256: sha256(raw),
    keys,
    authentication:
      "Retrieved from an explicitly configured official HTTPS URL using the host trust store; no JWT jku/x5u resolution. JWKS has no intrinsic expiry. Snapshot is provenance, not permanent authorization.",
    evidenceLimit:
      "Authentic public issuer keys only; no genuine credential or successful issuer-signature vector is implied.",
  };
}
