#!/usr/bin/env node
import { createPrivateKey, createPublicKey } from "node:crypto";
import { exportJWK, SignJWT } from "jose";
import { importVerifiedLinkedIn } from "credential-proofs-inputs/linkedin";

import { stringifyToml } from "credential-proofs-inputs/toml";

import { readFile, writeFile } from "node:fs/promises";

const output =
  process.argv[2] ??
  new URL("../../target/kat/linkedin/Prover.toml", import.meta.url);
// Reuse the committed intentionally public RSA4096 test key; never rotate it.
const privateKey = createPrivateKey(
  await readFile(
    new URL("../../fixtures/data/synthetic-rs256-4096-private.pem", import.meta.url),
  ),
);
const publicKey = createPublicKey(privateKey);
const jwk = await exportJWK(publicKey);
jwk.kid = "local-synthetic-linkedin-rs256-4096";
jwk.alg = "RS256";
const now = 1_900_000_000;
const token = await new SignJWT({ profile: { given_name: "Synthetic" } })
  .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" })
  .setIssuer("https://www.linkedin.com")
  .setAudience("synthetic-linkedin-client-id")
  .setSubject("synthetic-pairwise-subject")
  .setIssuedAt(now - 60)
  .setExpirationTime(now + 3600)
  .sign(privateKey);
const witness = await importVerifiedLinkedIn(
  token,
  {
    audience: "synthetic-linkedin-client-id",
    subject: "synthetic-pairwise-subject",
    now,
  },
  jwk,
);
await writeFile(output, stringifyToml(witness), { mode: 0o600 });
console.log(
  `wrote a synthetic LinkedIn-shape local verifier fixture to ${output}; it is not provider-issued`,
);
