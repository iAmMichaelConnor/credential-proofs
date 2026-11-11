/** Offline import: no personal QR is sent to any endpoint. */
import { readFile } from "node:fs/promises";
import { importVerifiedPhilSys } from "credential-proofs-inputs/philsys";

import { boundedBytes, writeToml } from "credential-proofs-inputs/toml";

const [qrFile, keyFile, output] = process.argv.slice(2);
if (!output)
  throw Error(
    "usage: node scripts/import-philsys.mjs LEGACY_QR_JSON TRUSTED_PUBLIC_KEY_JSON OUTPUT.toml",
  );
const keyMaterial = JSON.parse(await readFile(keyFile, "utf8"));
if (typeof keyMaterial.publicKeyBase64 !== "string")
  throw Error("trusted key file requires publicKeyBase64");
const key = Buffer.from(keyMaterial.publicKeyBase64, "base64");
if (key.length !== 32 || key.toString("base64") !== keyMaterial.publicKeyBase64)
  throw Error("Invalid trusted Ed25519 key");
const imported = importVerifiedPhilSys(await readFile(qrFile, "utf8"), key);
const auth = { ...imported.auth };
for (const k of Object.keys(auth))
  if (!["signature", "issuer_hint", "signature_hint"].includes(k))
    auth[k] = boundedBytes(Uint8Array.from(auth[k]), 64);
await writeToml(output, { auth, policy: imported.policy });
console.log(
  "Verified legacy PhilID issuer signature and wrote private credential witness. This does not establish holder control or current status.",
);
