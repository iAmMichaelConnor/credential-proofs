// Public maintainer WebAuthn test and deliberately local POD; no personal credentials.
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import assert from "node:assert/strict";
import { podToCircuitWitness } from "credential-proofs-inputs/zupass";

const root = new URL("../../../", import.meta.url);
const file = (p) => new URL(p, root);
const hash = (b) => createHash("sha256").update(b).digest("hex");
const passkeyPath = "fixtures/material/passkey/provider-test/oxide-assertion.toml";
const data = JSON.parse(
  execFileSync(
    "python3",
    [
      "-c",
      'import json,tomllib,sys;print(json.dumps(tomllib.load(open(sys.argv[1],"rb"))))',
      file(passkeyPath).pathname,
    ],
    { encoding: "utf8" },
  ),
);
const clientBytes = Buffer.from(
  data.assertion.client_data_json.slice(0, data.assertion.client_data_json_len),
);
const client = JSON.parse(clientBytes);
assert.equal(client.type, "webauthn.get");
assert.equal(
  client.origin,
  Buffer.from(data.policy.origin.slice(0, data.policy.origin_len)).toString(),
);
assert.equal(
  BigInt("0x" + Buffer.from(client.challenge, "base64url").toString("hex")),
  BigInt(data.challenge),
);
const sourcePath =
  "fixtures/material/passkey/provider-test/oxide-webauthn.nr";
const upstream = await readFile(file(sourcePath), "utf8");
function constant(name) {
  const match = new RegExp(`global ${name}:[^=]+=[ \n]*\\[([^\\]]+)\\]`).exec(
    upstream,
  );
  if (!match) throw Error("Missing upstream " + name);
  return Buffer.from(
    match[1]
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean)
      .map(Number),
  );
}
assert(constant("TEST_CLIENT_DATA_JSON").equals(clientBytes));
assert(
  constant("TEST_AUTHENTICATOR_DATA").equals(
    Buffer.from(data.assertion.authenticator_data),
  ),
);
assert(
  constant("TEST_SIGNATURE").equals(Buffer.from(data.assertion.signature)),
);
const auth = Buffer.from(data.assertion.authenticator_data);
assert(
  auth.subarray(0, 32).equals(
    createHash("sha256")
      .update(Buffer.from(data.policy.rp_id.slice(0, data.policy.rp_id_len)))
      .digest(),
  ),
);
assert((auth[32] & 1) !== 0);
if (data.policy.require_user_verification) assert((auth[32] & 4) !== 0);
const key = createPublicKey({
  key: {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(data.public_key.x).toString("base64url"),
    y: Buffer.from(data.public_key.y).toString("base64url"),
  },
  format: "jwk",
});
const signed = Buffer.concat([
  auth,
  createHash("sha256").update(clientBytes).digest(),
]);
const signature = Buffer.from(data.assertion.signature);
assert(verify("sha256", signed, { key, dsaEncoding: "ieee-p1363" }, signature));
const changed = Buffer.from(signed);
changed[0] ^= 1;
assert(
  !verify("sha256", changed, { key, dsaEncoding: "ieee-p1363" }, signature),
);
const podPath =
  "fixtures/data/generated/zupass.synthetic.toml.pod.json";
const pod = JSON.parse(await readFile(file(podPath), "utf8"));
const witness = podToCircuitWitness(pod, "event");
const altered = structuredClone(pod);
altered.entries.event = 43;
assert.throws(
  () => podToCircuitWitness(altered, "event"),
  /signature verification failed/,
);
const result = {
  verifier:
    process.version +
    " node:crypto P256 and @pcd/pod0.5.1 via shared podToCircuitWitness",
  passkey: {
    input: passkeyPath,
    sha256: hash(await readFile(file(passkeyPath))),
    upstreamSource: sourcePath,
    upstreamSourceSha256: hash(await readFile(file(sourcePath))),
    upstreamBytesMatch: true,
    signatureVerified: true,
    challengeOriginRpUvVerified: true,
    changedSignedBytesRejected: true,
    origin:
      "Pinned Oxide maintainer public test, not physical authenticator attestation",
  },
  zupass: {
    input: podPath,
    sha256: hash(await readFile(file(podPath))),
    signatureVerified: true,
    changedEntryRejected: true,
    contentId: witness.content_id,
    origin: "Local synthetic public test key; no issuer identity claim",
  },
};
console.log(JSON.stringify(result, null, 2));
console.log(
  "Public WebAuthn fixture and local POD signature/policy checks plus two negatives passed.",
);
