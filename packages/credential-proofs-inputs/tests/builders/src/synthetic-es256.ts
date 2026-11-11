/** Deterministic, public test-only P256 signing. Never enroll this key in production. */
import { p256 } from "@noble/curves/p256";
import { createHash } from "node:crypto";
import type { JWK } from "jose";
export function syntheticP256Jwk(kid = "repository-synthetic-p256"): JWK {
  const scalar = Buffer.alloc(32);
  scalar[31] = 42;
  const point = p256.getPublicKey(scalar, false);
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(point.slice(1, 33)).toString("base64url"),
    y: Buffer.from(point.slice(33)).toString("base64url"),
    alg: "ES256",
    use: "sig",
    kid,
  };
}
export function signSyntheticEs256(
  payload: Record<string, unknown>,
  kid = "repository-synthetic-p256",
): string {
  return signSyntheticEs256Raw(JSON.stringify(payload), kid);
}
export function signSyntheticEs256Raw(
  payload: string,
  kid = "repository-synthetic-p256",
): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "ES256", typ: "JWT", kid }),
  ).toString("base64url");
  const body = Buffer.from(payload).toString("base64url");
  const signed = header + "." + body;
  const scalar = Buffer.alloc(32);
  scalar[31] = 42;
  const digest = createHash("sha256").update(signed).digest();
  const signature = p256
    .sign(digest, scalar, { lowS: false })
    .toCompactRawBytes();
  return signed + "." + Buffer.from(signature).toString("base64url");
}
