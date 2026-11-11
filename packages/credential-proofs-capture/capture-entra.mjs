// Interactive operator action only. No client secret; authorization code + PKCE.
import { createServer } from "node:http";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { writeFile } from "node:fs/promises";
import {
  entraIssuer,
  importEntraToken,
} from "credential-proofs-inputs/entra";

const [tenant, clientId, nonce, output] = process.argv.slice(2);
if (!tenant || !clientId || !/^[0-9a-f]{64}$/.test(nonce ?? "") || !output)
  throw new Error(
    "Usage: node packages/credential-proofs-capture/capture-entra.mjs TENANT_GUID CLIENT_ID ACTION_NONCE_HEX OUTPUT_TOKEN_FILE",
  );
entraIssuer(tenant);
const redirect = "http://localhost:8765/callback";
const verifier = randomBytes(32).toString("base64url"),
  state = randomBytes(32).toString("base64url");
const url = new URL(
  `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
);
url.search = new URLSearchParams({
  client_id: clientId,
  response_type: "code",
  redirect_uri: redirect,
  response_mode: "query",
  scope: "openid profile",
  nonce,
  state,
  code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  code_challenge_method: "S256",
}).toString();
const server = createServer(async (req, res) => {
  try {
    const incoming = new URL(req.url ?? "/", redirect);
    if (incoming.pathname != "/callback") {
      res.writeHead(404).end();
      return;
    }
    const supplied = Buffer.from(incoming.searchParams.get("state") ?? "");
    if (
      supplied.length !== Buffer.byteLength(state) ||
      !timingSafeEqual(supplied, Buffer.from(state))
    )
      throw new Error("callback state mismatch");
    const code = incoming.searchParams.get("code");
    if (!code)
      throw new Error(
        incoming.searchParams.get("error_description") ??
          "authorization code missing",
      );
    const response = await fetch(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          redirect_uri: redirect,
          code,
          code_verifier: verifier,
        }),
      },
    );
    const body = await response.json();
    if (!response.ok || typeof body.id_token !== "string")
      throw new Error(body.error_description ?? "token endpoint rejected code");
    await writeFile(output, body.id_token + "\n", { mode: 0o600, flag: "wx" });
    const payload = JSON.parse(
      Buffer.from(body.id_token.split(".")[1], "base64url").toString("utf8"),
    );
    if (typeof payload.sub !== "string")
      throw new Error("token subject missing");
    const expected = {
      tenant,
      audience: clientId,
      subject: payload.sub,
      nonce,
      now: Math.floor(Date.now() / 1000),
    };
    await importEntraToken(body.id_token, expected);
    await writeFile(
      output + ".expected.json",
      JSON.stringify(expected, null, 2) + "\n",
      { mode: 0o600, flag: "wx" },
    );
    res.end("Token saved and verified locally. Return to your terminal.");
    console.log(
      `Verified token saved to ${output}; enrollment metadata saved to ${output}.expected.json. Review the subject before committing an account policy.`,
    );
    server.close();
  } catch (error) {
    res.writeHead(400).end("Capture failed. Check terminal.");
    console.error(error instanceof Error ? error.message : String(error));
    server.close();
    process.exitCode = 1;
  }
});
server.listen(8765, "127.0.0.1", () =>
  console.log(`Open this URL yourself to sign in:\n${url}`),
);
setTimeout(() => {
  console.error("Login timed out after 10 minutes");
  server.close();
  process.exitCode = 1;
}, 600000).unref();
