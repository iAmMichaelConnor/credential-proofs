import { readFile } from "node:fs/promises";
import { verify, createPublicKey, createHash } from "node:crypto";
const fixture = JSON.parse(
  await readFile(
    new URL("../../../fixtures/data/alipay/upstream-v2-file-upload.json", import.meta.url),
    "utf8",
  ),
);
const source = `https://raw.githubusercontent.com/alipay/alipay-sdk-nodejs-all/${fixture.provenance.commit}/test/alipay.test.ts`;
const response = await fetch(source, {
  redirect: "error",
  signal: AbortSignal.timeout(30000),
});
if (!response.ok)
  throw Error("Official pinned fixture source HTTP " + response.status);
const raw = await response.text();
if (!raw.includes(fixture.signature))
  throw Error(
    "Pinned official test source does not contain collected signature",
  );
const signature = Buffer.from(fixture.signature, "base64");
const valid = verify(
  "RSA-SHA256",
  Buffer.from(fixture.body),
  fixture.publicKeyPem,
  signature,
);
if (!valid) throw Error("Official recorded response signature failed");
if (
  verify(
    "RSA-SHA256",
    Buffer.from(fixture.body + " "),
    fixture.publicKeyPem,
    signature,
  )
)
  throw Error("Altered response accepted");
const wrong = await readFile(
  new URL("../../../fixtures/data/synthetic-rs256-public.pem", import.meta.url),
  "utf8",
);
if (verify("RSA-SHA256", Buffer.from(fixture.body), wrong, signature))
  throw Error("Wrong local key accepted");
const sha = (x) => createHash("sha256").update(x).digest("hex");
const report = {
  schemaVersion: 1,
  sourceUrl: source,
  fetchedAt: new Date().toISOString(),
  sourceSha256: sha(raw),
  recordedBodySha256: sha(fixture.body),
  spkiSha256: sha(
    createPublicKey(fixture.publicKeyPem).export({
      type: "spki",
      format: "der",
    }),
  ),
  algorithm: "RSA PKCS1v1.5 SHA256",
  verifier:
    process.version + " node:crypto/OpenSSL " + process.versions.openssl,
  result: "credential-signature-verified",
  alteredBodyRejected: true,
  wrongLocalKeyRejected: true,
  trustRole:
    "Alipay official SDK published test key/recorded upload response; not an identity credential and not independently authenticated production platform trust.",
};
console.log(JSON.stringify(report, null, 2));
console.log(
  "Official pinned Alipay test response signature verified; wrong key and altered body rejected",
);
