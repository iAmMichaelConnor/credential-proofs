// Explicit network check. This is deliberately not part of the offline test suite.
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { importPKCS8, SignJWT } from "jose";
import { rsaKeyToCircuit, importProviderToken } from "credential-proofs-inputs/oidc";

const key = await importPKCS8(
  await readFile(
    new URL("../../../fixtures/data/synthetic-rs256-private.pem", import.meta.url),
    "utf8",
  ),
  "RS256",
);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const reports = [];
for (const [provider, url, issuer] of [
  [
    "google",
    "https://www.googleapis.com/oauth2/v3/certs",
    "https://accounts.google.com",
  ],
  [
    "telegram",
    "https://oauth.telegram.org/.well-known/jwks.json",
    "https://oauth.telegram.org",
  ],
  ["apple", "https://appleid.apple.com/auth/keys", "https://appleid.apple.com"],
]) {
  const response = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`${provider}: HTTP ${response.status}`);
  const raw = await response.text();
  const jwks = JSON.parse(raw);
  const rsa = jwks.keys.filter(
    (k) => k.kty === "RSA" && (k.alg === undefined || k.alg === "RS256"),
  );
  const keys = rsa.map((k) => {
    const params = rsaKeyToCircuit(k);
    return {
      kid: k.kid,
      alg: k.alg,
      use: k.use,
      modulusLimbs: params.modulus_limbs.length,
      redcLimbs: params.redc_params_limbs.length,
    };
  });
  if (!keys.length) throw new Error(`${provider}: no compatible RSA keys`);
  // A real provider kid with a local test-key signature must still fail.
  const now = Math.floor(Date.now() / 1000);
  const expected = {
    audience: "local-negative-test",
    subject: "test-subject",
    nonce: "test-nonce",
    now,
  };
  const token = await new SignJWT({ nonce: expected.nonce })
    .setProtectedHeader({ alg: "RS256", kid: keys[0].kid })
    .setIssuer(issuer)
    .setAudience(expected.audience)
    .setSubject(expected.subject)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
  let rejection;
  try {
    await importProviderToken(provider, token, expected);
  } catch (error) {
    rejection = error.code;
  }
  if (rejection !== "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
    throw new Error(
      `${provider}: unexpected counterfeit-token result ${rejection}`,
    );
  reports.push({
    provider,
    url,
    fetchedAt: new Date().toISOString(),
    responseSha256: sha(raw),
    keys,
    counterfeitProviderKidSignature: rejection,
  });
  console.log(
    `${provider}: ${keys.length} public RSA keys converted; counterfeit provider-kid signature rejected`,
  );
}
console.log(
  JSON.stringify(
    {
      scope:
        "Fixed-provider HTTPS JWKS ingestion and key conversion; rejection of local signatures carrying a real provider kid. No user login or genuine ID token was obtained.",
      sourceSha256: sha(
        await readFile(new URL("../../../packages/credential-proofs-inputs/src/oidc.ts", import.meta.url)),
      ),
      executedModuleSha256: sha(
        await readFile(new URL("../../../packages/credential-proofs-inputs/dist/src/oidc.js", import.meta.url)),
      ),
      reports,
    },
    null,
    2,
  ) + "\n",
);
