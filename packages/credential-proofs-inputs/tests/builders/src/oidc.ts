/** Public synthetic signing keys; test fixtures only. */
import { readFile } from "node:fs/promises";
import { exportJWK, importPKCS8, importSPKI, SignJWT, type JWK } from "jose";
import { importVerifiedOidc, type Provider, type OidcExpected } from "credential-proofs-inputs/oidc";
import { publicOidcSources } from "credential-proofs-inputs/provider-config";
import { writeToml, type TomlDocument } from "credential-proofs-inputs/toml";
const rsaFixtureKey = new URL("../../../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url);
const rsaFixturePublicKey = new URL("../../../../../fixtures/data/synthetic-rs256-public.pem", import.meta.url);
export async function createSyntheticOidc(
  provider: Provider,
  expected: OidcExpected,
): Promise<{ token: string; jwk: JWK; document: TomlDocument }> {
  const [privatePem, publicPem] = await Promise.all([
    readFile(rsaFixtureKey, "utf8"),
    readFile(rsaFixturePublicKey, "utf8"),
  ]);
  const privateKey = await importPKCS8(privatePem, "RS256");
  const publicKey = await importSPKI(publicPem, "RS256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "local-synthetic-rs256";
  jwk.alg = "RS256";
  jwk.use = "sig";
  const configuredIssuer = publicOidcSources[provider].issuer;
  const issuer =
    typeof configuredIssuer === "string"
      ? configuredIssuer
      : configuredIssuer[0]!;
  const token = await new SignJWT({ nonce: expected.nonce })
    .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(expected.audience)
    .setSubject(expected.subject)
    .setIssuedAt(expected.now - 60)
    .setExpirationTime(expected.now + 3600)
    .sign(privateKey);
  return {
    token,
    jwk,
    document: await importVerifiedOidc(provider, token, expected, jwk),
  };
}

export async function writeOidcFixture(
  outputPath: string,
  provider: Provider,
  expected: OidcExpected,
): Promise<void> {
  const result = await createSyntheticOidc(provider, expected);
  await writeToml(outputPath, result.document);
}

