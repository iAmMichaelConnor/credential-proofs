// Run only by the legitimate service operator. No login/app creation is automatic.
import { randomBytes, createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import { govbrIssuer, importGovbrToken, assuranceRank } from "credential-proofs-inputs/govbr";

const [environment, client, redirect, subject, nonce, minimumLevel, output] =
  process.argv.slice(2);
if (
  !environment ||
  !client ||
  !redirect ||
  !subject ||
  !/^[0-9a-f]{64}$/.test(nonce ?? "") ||
  !assuranceRank(minimumLevel) ||
  !output
)
  throw Error(
    "Usage: capture-govbr.mjs production|staging CLIENT_ID REGISTERED_HTTPS_REDIRECT EXPECTED_SUBJECT ACTION_NONCE_HEX bronze|silver|gold PRIVATE_OUTPUT.jwt",
  );
const issuer = govbrIssuer(environment);
const callback = new URL(redirect);
if (callback.protocol !== "https:" || callback.hash || callback.search)
  throw Error(
    "Use the exact registered HTTPS redirect URI without query or fragment",
  );
const secret = process.env.GOVBR_CLIENT_SECRET;
if (!secret)
  throw Error(
    "Set GOVBR_CLIENT_SECRET for your legitimately registered confidential client",
  );
const state = randomBytes(32).toString("base64url"),
  verifier = randomBytes(32).toString("base64url");
const challenge = createHash("sha256").update(verifier).digest("base64url");
const authorize = new URL("authorize", issuer);
authorize.search = new URLSearchParams({
  response_type: "code",
  client_id: client,
  redirect_uri: redirect,
  scope: "openid govbr_confiabilidades_idtoken",
  nonce,
  state,
  code_challenge: challenge,
  code_challenge_method: "S256",
}).toString();
console.log(
  "Open this URL in your browser and complete your own gov.br login:",
);
console.log(authorize.href);
const rl = createInterface({ input: process.stdin, output: process.stdout });
let received;
try {
  received = new URL(
    (
      await rl.question(
        "Paste the complete registered redirect URL after login: ",
      )
    ).trim(),
  );
} finally {
  rl.close();
}
if (
  received.origin !== callback.origin ||
  received.pathname !== callback.pathname ||
  received.searchParams.get("state") !== state ||
  received.searchParams.has("error")
)
  throw Error("redirect/state mismatch or authorization refused");
const code = received.searchParams.get("code");
if (!code) throw Error("redirect has no authorization code");
const response = await fetch(new URL("token", issuer), {
  method: "POST",
  redirect: "error",
  headers: {
    "content-type": "application/x-www-form-urlencoded",
    authorization:
      "Basic " + Buffer.from(client + ":" + secret).toString("base64"),
  },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirect,
    code_verifier: verifier,
  }),
  signal: AbortSignal.timeout(30000),
});
if (!response.ok) throw Error("gov.br token endpoint HTTP " + response.status);
const result = await response.json();
if (typeof result.id_token !== "string")
  throw Error("provider did not return ID token");
const expected = {
  environment,
  audience: client,
  subject,
  nonce,
  minimumLevel,
  now: Math.floor(Date.now() / 1000),
};
await importGovbrToken(result.id_token, expected);
await writeFile(output, result.id_token + "\n", { mode: 0o600, flag: "wx" });
await writeFile(
  output + ".expected.json",
  JSON.stringify(expected, null, 2) + "\n",
  { mode: 0o600, flag: "wx" },
);
console.log(
  "Verified signature, exact identity/session/environment and signed assurance. Saved private token and expected-policy record.",
);
