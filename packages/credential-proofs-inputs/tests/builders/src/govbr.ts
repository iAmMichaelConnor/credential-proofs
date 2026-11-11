/** Locally signed gov.br-shaped token; test fixtures only. */
import { readFile } from "node:fs/promises";
import { exportJWK, importPKCS8, importSPKI, SignJWT, type JWK } from "jose";
import { importVerifiedGovbr, govbrIssuer, type GovbrExpected, type AssuranceLevel } from "credential-proofs-inputs/govbr";
import type { TomlDocument } from "credential-proofs-inputs/toml";
export async function createSyntheticGovbr(
  expected: GovbrExpected,
  level: AssuranceLevel = "gold",
): Promise<{ token: string; jwk: JWK; document: TomlDocument }> {
  const [priv, pub] = await Promise.all([
    readFile(
      new URL("../../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../../../../fixtures/data/synthetic-rs256-public.pem", import.meta.url),
      "utf8",
    ),
  ]);
  const key = await importPKCS8(priv, "RS256");
  const jwk = await exportJWK(await importSPKI(pub, "RS256"));
  jwk.kid = "local-synthetic-rs256";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const token = await new SignJWT({
    nonce: expected.nonce,
    amr: ["passwd", "mfa", "otp_offline"],
    scope: ["openid", "govbr_confiabilidades_idtoken"],
    reliability_info: {
      level,
      reliabilities: [
        { id: "601", updatedAt: "2025-07-02T14:17:16.001-0300" },
        { id: "626" },
      ],
    },
  })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" })
    .setIssuer(govbrIssuer(expected.environment))
    .setAudience(expected.audience)
    .setSubject(expected.subject)
    .setIssuedAt(expected.now - 5)
    .setExpirationTime(expected.now + 60)
    .sign(key);
  return {
    token,
    jwk,
    document: await importVerifiedGovbr(token, expected, jwk),
  };
}
