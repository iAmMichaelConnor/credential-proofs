import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { keccak256, verifyTypedData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
const root = new URL("../../", import.meta.url);
const source = new URL(
  "fixtures/data/peer-v4-synthetic-payment.json",
  root,
);
const fixture = JSON.parse(await readFile(source, "utf8"));
const hex = (x) => Buffer.from(x.slice(2), "hex");
const word = (value) => {
  let x = BigInt(value);
  const b = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 255n);
    x >>= 8n;
  }
  if (x !== 0n) throw Error("word overflow");
  return b;
};
const method = hex(
  "0x3ccc3d4d5e769b1f82dc4988485551dc0cd3c7a3926d7d8a4dde91507199490f",
);
const payee = hex(
  "0x491ed026adf1480ca9b90cb5d0ee91392392af9219a965024486c9d3c0f2d7af",
);
const currency = hex(
  "0xc4ae21aac0c6549d71dd96035b7e0bdb6c79ebdba8891b666115bc976d16a29e",
);
const paymentId = hex(
  "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702af6",
);
const intent = hex(fixture.intentHash);
const timestamp = BigInt(fixture.paymentTimestampMs);
const data = Buffer.concat([
  method,
  payee,
  word(10000),
  currency,
  word(timestamp),
  paymentId,
  intent,
  word(500),
  method,
  currency,
  payee,
  word(10n ** 18n),
  word(timestamp),
  word(60000),
  word(0),
  word(512),
  word(0),
]);
if (data.length !== 544 || keccak256(data) !== fixture.dataHash)
  throw Error("existing payment ABI/hash mismatch");
const account = privateKeyToAccount(`0x${"0".repeat(63)}1`);
const typed = {
  domain: {
    name: "UnifiedPaymentVerifier",
    version: "1",
    chainId: 8453,
    verifyingContract: `0x${"11".repeat(20)}`,
  },
  primaryType: "PaymentAttestation",
  types: {
    PaymentAttestation: [
      { name: "intentHash", type: "bytes32" },
      { name: "releaseAmount", type: "uint256" },
      { name: "dataHash", type: "bytes32" },
    ],
  },
  message: {
    intentHash: fixture.intentHash,
    releaseAmount: 400n,
    dataHash: fixture.dataHash,
  },
};
const verified = await verifyTypedData({
  ...typed,
  address: account.address,
  signature: fixture.signature,
});
if (!verified || (await account.signTypedData(typed)) !== fixture.signature)
  throw Error("existing synthetic attestor signature mismatch");
const pub = hex(account.publicKey);
const attestation = {
  intent_hash: intent,
  release_amount: word(400),
  data_hash: hex(fixture.dataHash),
  data,
  data_len: 544,
  signature: hex(fixture.signature),
};
const policy = {
  chain_id: 8453,
  verifier_address: Buffer.alloc(20, 17),
  attestor_x: pub.subarray(1, 33),
  attestor_y: pub.subarray(33, 65),
  attestor_address: hex(account.address),
  expected_intent_hash: intent,
  expected_method: method,
  expected_payee_id: payee,
  expected_currency: currency,
  expected_token_amount: word(500),
  expected_conversion_rate: word(10n ** 18n),
  expected_signal_timestamp_ms: word(timestamp),
  expected_timestamp_buffer_ms: word(60000),
  expected_payer_commitment_hash: word(0),
  expected_release_amount: word(400),
  min_fiat_amount: word(10000),
  max_payment_age_ms: 60000,
};
const tomlValue = (x) =>
  Buffer.isBuffer(x) ? JSON.stringify([...x]) : String(x);
let toml = "now = 1900000000\n";
for (const [name, obj] of Object.entries({ attestation, policy })) {
  toml += `\n[${name}]\n`;
  for (const [k, v] of Object.entries(obj)) toml += `${k} = ${tomlValue(v)}\n`;
}
await writeFile(
  new URL("target/kat/peer_v4/Prover.toml", root),
  toml,
);
const report = {
  scope:
    "Existing local synthetic Peer V4 attestor payment; not provider-issued and not holder action proof",
  sourceFixture:
    "fixtures/data/peer-v4-synthetic-payment.json",
  sourceSha256: createHash("sha256")
    .update(await readFile(source))
    .digest("hex"),
  dataHash: fixture.dataHash,
  signature: fixture.signature,
  attestor: account.address,
  publicTestPrivateScalar: "1",
  verifyTypedData: verified,
  byteLength: data.length,
};
console.log(JSON.stringify(report));
