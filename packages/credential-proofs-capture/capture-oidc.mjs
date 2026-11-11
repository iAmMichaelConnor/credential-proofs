// Optional local authorization-code capture for reviewed fixed providers.
// No app registration, login, private-token storage or network call occurs until invoked.
import { randomBytes, createHash } from "node:crypto";
import { createInterface } from "node:readline/promises";
import { writeFile } from "node:fs/promises";
import { importProviderToken } from "credential-proofs-inputs/oidc";

const config = {
  miargentina: {
    authorize: "https://id.argentina.gob.ar/authorize",
    token: "https://id.argentina.gob.ar/token",
    secret: "MIARGENTINA_CLIENT_SECRET",
    pkce: false,
  },
  kakao: {
    authorize: "https://kauth.kakao.com/oauth/authorize",
    token: "https://kauth.kakao.com/oauth/token",
    secret: "KAKAO_CLIENT_SECRET",
    pkce: true,
  },
};
const [provider, client, redirect, subject, nonce, output] =
  process.argv.slice(2);
const selected = config[provider];
if (
  !selected ||
  !client ||
  !redirect ||
  !subject ||
  !output ||
  !/^[0-9a-f]{64}$/.test(nonce ?? "")
)
  throw Error(
    "Usage: capture-oidc.mjs miargentina|kakao CLIENT REGISTERED_REDIRECT EXACT_SUBJECT ACTION_HEX PRIVATE_OUTPUT",
  );
const callback = new URL(redirect);
if (
  callback.protocol !== "https:" &&
  !(
    callback.protocol === "http:" &&
    ["127.0.0.1", "localhost"].includes(callback.hostname)
  )
)
  throw Error("HTTPS or registered loopback redirect required");
const state = randomBytes(32).toString("base64url");
const verifier = randomBytes(32).toString("base64url");
const auth = new URL(selected.authorize);
auth.search = new URLSearchParams({
  client_id: client,
  redirect_uri: redirect,
  response_type: "code",
  scope: "openid",
  nonce,
  state,
}).toString();
if (selected.pkce) {
  auth.searchParams.set(
    "code_challenge",
    createHash("sha256").update(verifier).digest("base64url"),
  );
  auth.searchParams.set("code_challenge_method", "S256");
}
console.log("Open with your own approved application:\n" + auth);
const input = createInterface({ input: process.stdin, output: process.stdout });
let raw;
try {
  raw = await input.question("Paste the final callback URL: ");
} finally {
  input.close();
}
const result = new URL(raw);
if (
  result.origin !== callback.origin ||
  result.pathname !== callback.pathname ||
  result.searchParams.get("state") !== state
)
  throw Error("Callback origin/path/state mismatch");
const code = result.searchParams.get("code");
if (!code || result.searchParams.has("error"))
  throw Error("No authorization code");
const body = new URLSearchParams({
  grant_type: "authorization_code",
  client_id: client,
  redirect_uri: redirect,
  code,
});
if (selected.pkce) body.set("code_verifier", verifier);
const secret = process.env[selected.secret];
if (secret) body.set("client_secret", secret);
else if (provider === "miargentina")
  throw Error(
    "Set your own MIARGENTINA_CLIENT_SECRET; documentation example secrets are not authorized credentials",
  );
const response = await fetch(selected.token, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body,
  redirect: "error",
  signal: AbortSignal.timeout(30000),
});
if (!response.ok) throw Error("Token endpoint HTTP " + response.status);
const value = await response.json();
if (typeof value.id_token !== "string") throw Error("No ID token returned");
const expected = {
  audience: client,
  subject,
  nonce,
  now: Math.floor(Date.now() / 1000),
};
await importProviderToken(provider, value.id_token, expected);
await writeFile(output, value.id_token + "\n", { mode: 0o600, flag: "wx" });
await writeFile(
  output + ".expected.json",
  JSON.stringify(expected, null, 2) + "\n",
  { mode: 0o600, flag: "wx" },
);
console.log(
  "Verified original ID token saved privately; no access/refresh token saved.",
);
