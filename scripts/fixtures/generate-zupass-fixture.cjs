// Synthetic public test key, never a production credential. Requires @pcd/pod@0.5.1.
const { createRequire } = require("node:module");
const credentialsRequire = createRequire(
  require("path").resolve(__dirname, "../../packages/credential-proofs-inputs/package.json"),
);
const { POD } = credentialsRequire("@pcd/pod");
const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "../..");
const example = path.join(root, "target/kat/zupass_pod");
const key = "0001020304050607080900010203040506070809000102030405060708090001";
const pod = POD.sign(
  { event: { type: "int", value: 42n }, owner: { type: "int", value: 7n } },
  key,
);
const { decodePublicKey, decodeSignature } = credentialsRequire("@pcd/pod");
const pk = decodePublicKey(pod.signerPublicKey),
  sig = decodeSignature(pod.signature);
const proof = pod.content.generateEntryProof("event");
const out = {
  sdk: "@pcd/pod@0.5.1",
  pod: pod.toJSON(),
  issuer: { x: pk[0], y: pk[1] },
  signature: { rx: sig.R8[0], ry: sig.R8[1], s: sig.S },
  content_id: pod.contentID,
  name_hash: proof.leaf,
  value_hash: proof.siblings[0],
  depth: proof.siblings.length - 1,
  indices: Array.from(
    { length: 8 },
    (_, i) => !!((proof.index >> (i + 1)) & 1),
  ),
  siblings: [
    ...proof.siblings.slice(1),
    ...Array(8 - (proof.siblings.length - 1)).fill(0n),
  ],
};
fs.writeFileSync(
  path.join(root, "fixtures/data/zupass/fixture.json"),
  JSON.stringify(out, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2) +
    "\n",
);
const lines = [
  'content_id = "' + out.content_id + '"',
  'name_hash = "' + out.name_hash + '"',
  'value_hash = "' + out.value_hash + '"',
  "depth = " + out.depth,
  "indices = " + JSON.stringify(out.indices),
  "siblings = " + JSON.stringify(out.siblings.map(String)),
];
for (const n of ["issuer", "signature"]) {
  lines.push("[" + n + "]");
  for (const [k, v] of Object.entries(out[n])) lines.push(k + ' = "' + v + '"');
}
fs.writeFileSync(path.join(example, "Prover.toml"), lines.join("\n") + "\n");
