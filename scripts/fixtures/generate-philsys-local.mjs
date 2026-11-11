import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { importVerifiedPhilSys } from "credential-proofs-inputs/philsys";

const root = new URL("../../", import.meta.url);
const sk = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, 42),
    ]),
    format: "der",
    type: "pkcs8",
  }),
  pk = createPublicKey(sk),
  key = Buffer.from(pk.export({ format: "jwk" }).x, "base64url");
const fields = {
  DateIssued: "31 May 2021",
  Issuer: "PSA",
  subject: {
    Suffix: "",
    lName: "TEST",
    fName: "SYNTHETIC",
    mName: "ONLY",
    sex: "Female",
    BF: "[1,10]",
    DOB: "March 01, 1947",
    POB: "Synthetic Town",
    PCN: "0000-0000-0000-0000",
  },
  alg: "EDDSA",
};
const message = Buffer.from(JSON.stringify(fields, null, 2), "latin1");
const qr = { ...fields, signature: sign(null, message, sk).toString("base64") };
const imported = importVerifiedPhilSys(JSON.stringify(qr), key);
const dir = new URL("../../fixtures/material/philsys/local-test/", import.meta.url);
await mkdir(dir, { recursive: true });
await writeFile(
  new URL("synthetic-legacy-qr.json", dir),
  JSON.stringify(qr, null, 2) + "\n",
);
await writeFile(
  new URL("synthetic-issuer-key.json", dir),
  JSON.stringify(
    {
      publicKeyBase64: key.toString("base64"),
      privateSeedHex: Buffer.alloc(32, 42).toString("hex"),
      warning: "PUBLIC LOCAL TEST KEY ONLY. Not PSA-issued.",
    },
    null,
    2,
  ) + "\n",
);
await writeFile(
  new URL("verified-witness.json", dir),
  JSON.stringify(
    { ...imported, signedMessage: message.toString("hex") },
    null,
    2,
  ) + "\n",
);
const arr = (b) => "[" + b.join(",") + "]",
  bv = (b) => "BoundedVec::from_array(" + arr(b) + ")",
  hint = (h) =>
    "PointHint{x_limbs:" + arr(h.x_limbs) + ",y_limbs:" + arr(h.y_limbs) + "}";
let f =
  "// Generated local synthetic issuer, never PSA-issued.\nuse crate::{AuthInput,AuthPolicy};\nuse ed25519_auth::PointHint;\npub fn fixture()->(AuthInput,AuthPolicy){(AuthInput{";
for (const [k, v] of Object.entries(imported.auth))
  f +=
    k +
    ":" +
    (k.endsWith("hint") ? hint(v) : k === "signature" ? arr(v) : bv(v)) +
    ",";
f +=
  "},AuthPolicy{issuer_key:" +
  arr(imported.policy.issuer_key) +
  ",credential_digest:" +
  arr(imported.policy.credential_digest) +
  "})}\n";
await writeFile(
  new URL("noir/philsys_auth/src/fixture.nr", root),
  f,
);
console.log(
  "Generated synthetic PhilSys legacy fixture and independently verified strict Ed25519 host import.",
);
const { localP256Key: p256, signLocalP256 } = await import(
  "./lib/local-p256-key.mjs"
);
const { stringifyToml, boundedBytes } = await import("../../packages/credential-proofs-inputs/dist/src/toml.js");
const { createHash } = await import("node:crypto");
const attestor = p256(43),
  holder = p256(44),
  action = Buffer.alloc(32),
  checked_at = 1899999940,
  expires_at = 1900003600,
  now = 1900000000;
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const statementMessage = Buffer.concat([
    Buffer.from("credential-proofs.philsys.legacy.enrollment.v1"),
    Buffer.from(imported.policy.credential_digest),
    Buffer.from(holder.key.public_key_x),
    Buffer.from(holder.key.public_key_y),
    action,
    u64(checked_at),
    u64(expires_at),
  ]),
  statement = createHash("sha256").update(statementMessage).digest();
const enrollment = {
  checked_at,
  expires_at,
  attestor_signature: [...signLocalP256(43, statementMessage)],
  holder_signature: [
    ...signLocalP256(
      44,
      Buffer.concat([Buffer.from("credential-proofs.philsys.legacy.holder.v1"), statement]),
    ),
  ],
};
const enrollment_policy = {
  attestor: attestor.key,
  holder: holder.key,
  max_status_age: 300,
};
const auth = { ...imported.auth };
for (const k of Object.keys(auth))
  if (!["signature", "issuer_hint", "signature_hint"].includes(k))
    auth[k] = boundedBytes(Uint8Array.from(auth[k]), 64);
const witness = {
  auth,
  policy: imported.policy,
  enrollment,
  enrollment_policy,
  action_digest: [...action],
  now,
};
await writeFile(
  new URL("target/kat/philsys/Prover.toml", root),
  stringifyToml({ auth, policy: imported.policy }),
);
await writeFile(
  new URL("enrollment-witness.json", dir),
  JSON.stringify(witness, null, 2) + "\n",
);
