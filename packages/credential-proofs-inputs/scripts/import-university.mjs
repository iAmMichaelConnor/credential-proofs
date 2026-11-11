/** Offline institutional token import; '-' JWKS fetch is CILogon-only. */
import { readFile } from "node:fs/promises";
import { importVerifiedUniversity, importCilogonToken } from "credential-proofs-inputs/university";

import { writeToml } from "credential-proofs-inputs/toml";

const [tokenFile, policyFile, jwksFile, output] = process.argv.slice(2);
if (!output)
  throw Error(
    "usage: node scripts/import-university.mjs TOKEN_FILE POLICY_JSON TRUSTED_JWKS_JSON_OR_DASH OUTPUT.toml",
  );
const token = (await readFile(tokenFile, "utf8")).trim(),
  policy = JSON.parse(await readFile(policyFile, "utf8"));
let document;
if (jwksFile === "-") {
  if (policy.mode !== "cilogon" || policy.issuer !== "https://cilogon.org")
    throw Error("automatic key fetch is fixed CILogon only");
  document = await importCilogonToken(token, policy);
} else {
  const header = JSON.parse(
      Buffer.from(token.split(".")[0] ?? "", "base64url").toString("utf8"),
    ),
    body = JSON.parse(await readFile(jwksFile, "utf8"));
  const keys = (Array.isArray(body.keys) ? body.keys : [body]).filter(
    (k) =>
      k.kid === header.kid &&
      k.kty === "RSA" &&
      (k.alg === undefined || k.alg === "RS256") &&
      (k.use === undefined || k.use === "sig"),
  );
  if (keys.length !== 1)
    throw Error("selected issuer kid must uniquely match trusted public JWK");
  document = await importVerifiedUniversity(token, policy, keys[0]);
}
await writeToml(output, document);
console.log(
  "Verified institutional OIDC login and wrote private witness. No current student/staff freshness is implied.",
);
