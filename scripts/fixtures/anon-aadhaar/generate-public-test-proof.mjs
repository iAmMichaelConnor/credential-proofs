import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";

const repo = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../",
);
const upstream = process.env.ANON_AADHAAR_SOURCE_DIR;
const artifacts = process.env.ANON_AADHAAR_ARTIFACT_DIR;
const out = process.env.ANON_AADHAAR_OUTPUT_DIR;
const snarkjsRoot = process.env.ANON_AADHAAR_SNARKJS_DIR;
const actionArg = process.argv[2];
if (!upstream || !artifacts || !out || !snarkjsRoot || !actionArg)
  throw new Error(
    "Set ANON_AADHAAR_SOURCE_DIR, ANON_AADHAAR_ARTIFACT_DIR, ANON_AADHAAR_OUTPUT_DIR, ANON_AADHAAR_SNARKJS_DIR, and pass the decimal uint256 action signal",
  );

const action = BigInt(actionArg);
if (action < 0n || action >= 1n << 256n)
  throw new Error("action signal must fit uint256");
const { groth16 } = await import(
  pathToFileURL(path.join(snarkjsRoot, "node_modules/snarkjs/main.js"))
);
const { keccak256 } = await import(
  pathToFileURL(
    path.join(
      repo,
      "node_modules/viem/_esm/index.js",
    ),
  )
);
const outputDir = path.resolve(out);
await fs.mkdir(outputDir, { recursive: true });

const fixture = JSON.parse(
  await fs.readFile(
    path.join(upstream, "packages/circuits/assets/test.json"),
    "utf8",
  ),
);
const qr = BigInt(fixture.testQRData);
let qrHex = qr.toString(16);
if (qrHex.length % 2) qrHex = `0${qrHex}`;
const decoded = inflateSync(Buffer.from(qrHex, "hex"));
if (decoded.length < 257)
  throw new Error(`Unexpected public test QR length ${decoded.length}`);
const signed = decoded.subarray(0, decoded.length - 256);
const signatureBytes = decoded.subarray(decoded.length - 256);
const padded = [...signed, 128];
const bitLen = BigInt(signed.length * 8);
while ((padded.length + 8) % 64 !== 0) padded.push(0);
for (let i = 7; i >= 0; i--)
  padded.push(Number((bitLen >> BigInt(i * 8)) & 255n));
const paddedLength = padded.length;
while (padded.length < 1536) padded.push(0);
if (padded.length !== 1536)
  throw new Error(`Public QR needs ${padded.length} padded bytes`);
const delimiterIndices = [];
for (let i = 0; i < padded.length && delimiterIndices.length < 18; i++)
  if (padded[i] === 255) delimiterIndices.push(i);
if (delimiterIndices.length !== 18)
  throw new Error(`Expected 18 delimiters, got ${delimiterIndices.length}`);
const certificate = await fs.readFile(
  path.join(upstream, "packages/circuits/assets/testCertificate.pem"),
);
const jwk = crypto.createPublicKey(certificate).export({ format: "jwk" });
const modulus = BigInt(`0x${Buffer.from(jwk.n, "base64url").toString("hex")}`);
const chunk = (n) => {
  const words = [];
  for (let i = 0; i < 17; i++) {
    words.push((n & ((1n << 121n) - 1n)).toString());
    n >>= 121n;
  }
  if (n !== 0n)
    throw new Error("RSA integer does not fit upstream 17 x 121-bit format");
  return words;
};
const signalBytes = `0x${action.toString(16).padStart(64, "0")}`;
const signalHash = (BigInt(keccak256(signalBytes)) >> 3n).toString();
const input = {
  qrDataPadded: padded.map(String),
  qrDataPaddedLength: paddedLength,
  delimiterIndices,
  signature: chunk(BigInt(`0x${signatureBytes.toString("hex")}`)),
  pubKey: chunk(modulus),
  nullifierSeed: "12345678",
  signalHash,
  revealAgeAbove18: "1",
  revealGender: "1",
  revealPinCode: "0",
  revealState: "0",
};
await fs.writeFile(path.join(outputDir, "input.json"), JSON.stringify(input));

const wasmPath = path.join(artifacts, "aadhaar-verifier.wasm");
const zkeyPath = path.join(artifacts, "circuit_final.zkey");
const verificationKey = JSON.parse(
  await fs.readFile(
    path.join(
      repo,
      "fixtures/material/anon_aadhaar/provider-public/vkey.json",
    ),
    "utf8",
  ),
);
const logger = { debug() {}, info() {}, warn() {}, error() {} };
const { proof, publicSignals } = await groth16.fullProve(
  input,
  wasmPath,
  zkeyPath,
  logger,
  {},
  { singleThread: true },
);
const verified = await groth16.verify(
  verificationKey,
  publicSignals,
  proof,
  logger,
);
if (!verified)
  throw new Error("snarkjs rejected the generated public-test proof");
await fs.writeFile(
  path.join(outputDir, "proof.json"),
  `${JSON.stringify(proof, null, 2)}\n`,
);
await fs.writeFile(
  path.join(outputDir, "public_signals.json"),
  `${JSON.stringify(publicSignals, null, 2)}\n`,
);
const sha256 = async (file) =>
  crypto
    .createHash("sha256")
    .update(await fs.readFile(file))
    .digest("hex");
const result = {
  schema: "anon-aadhaar-action-test-proof-v1",
  verified,
  actionSignal: action.toString(),
  actionSignalBytes: signalBytes,
  signalHash,
  publicSignals,
  proofSha256: await sha256(path.join(outputDir, "proof.json")),
  publicSignalsSha256: await sha256(
    path.join(outputDir, "public_signals.json"),
  ),
  wasmSha256: await sha256(wasmPath),
  zkeySha256: await sha256(zkeyPath),
  qrFixture: "anon-aadhaar/anon-aadhaar/packages/circuits/assets/test.json",
};
await fs.writeFile(
  path.join(outputDir, "proof-result.json"),
  `${JSON.stringify(result, null, 2)}\n`,
);
console.log(JSON.stringify(result, null, 2));
