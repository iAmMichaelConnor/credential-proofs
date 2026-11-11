// Writes src/fixture.nr and fixtures/manifest.json for the Peer V4
// payment-settlement instance. The attestations are synthetic: they are
// signed with the public secp256k1 test scalar 1, which is not a Peer
// witness, and record no payment.
//
// node scripts/fixtures/generators/peer_v4.mjs --instance payment-settlement/peer_v4 [--now <unix s>]
//
// The order pins the intent hash, which does not depend
// on the contract address, so one run writes the whole fixture. Needs
// `npm ci` in aztec/use-cases (viem). No network access, no proving.
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const { keccak256, encodePacked } = await import("viem");
const { privateKeyToAccount } = await import("viem/accounts");
const generator = "aztec/use-cases/scripts/fixtures/generators/peer_v4.mjs";
const CAPACITY = 1024;
// BN254 scalar field (Peer's CIRCOM_PRIME_FIELD).
const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hex = (x) => Buffer.from(x.replace(/^0x/, ""), "hex");
const word = (value) => {
  let x = BigInt(value);
  const b = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 255n);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error("word overflow");
  return b;
};
const bytes = (b, indent = "            ") => {
  const values = [...b];
  const lines = [];
  for (let i = 0; i < values.length; i += 16)
    lines.push(values.slice(i, i + 16).join(", "));
  return `[\n${indent}${lines.join(`,\n${indent}`)},\n${indent.slice(4)}]`;
};

// Peer's _calculateIntentHash: keccak256(orchestrator || counter) mod p.
const intentHash = (orchestrator, counter) =>
  word(
    BigInt(
      keccak256(encodePacked(["address", "uint256"], [orchestrator, counter])),
    ) % P,
  );

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      now: { type: "string", default: "4000000000" },
      "max-age-ms": { type: "string", default: "3600000" },
    },
  });
  if (values.instance !== "payment-settlement/peer_v4")
    throw new Error("Pass --instance payment-settlement/peer_v4");
  const now = BigInt(values.now);
  const maxAgeMs = BigInt(values["max-age-ms"]);
  const account = privateKeyToAccount(`0x${"0".repeat(63)}1`);
  const publicKey = hex(account.publicKey);
  const chainId = 8453;
  const verifier = `0x${"11".repeat(20)}`;
  const orchestrator = `0x${"22".repeat(20)}`;
  // The method, payee and currency hashes of the library's test vector.
  const base = {
    method: hex(
      "0x3ccc3d4d5e769b1f82dc4988485551dc0cd3c7a3926d7d8a4dde91507199490f",
    ),
    payee: hex(
      "0x491ed026adf1480ca9b90cb5d0ee91392392af9219a965024486c9d3c0f2d7af",
    ),
    currency: hex(
      "0xc4ae21aac0c6549d71dd96035b7e0bdb6c79ebdba8891b666115bc976d16a29e",
    ),
    fiat: 10000n,
    paidMs: now * 1000n - 60000n,
    paymentId: hex(
      "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702af6",
    ),
    intent: intentHash(orchestrator, 1n),
  };
  const variants = {
    payment: {},
    other_payment: {
      paymentId: hex(
        "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702af7",
      ),
    },
    other_amount: {
      fiat: 9999n,
      paymentId: hex(
        "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702af8",
      ),
    },
    other_payee: {
      payee: hex(
        "0x491ed026adf1480ca9b90cb5d0ee91392392af9219a965024486c9d3c0f2d7b0",
      ),
      paymentId: hex(
        "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702af9",
      ),
    },
    // Paid 600 001 ms before the intent's signal time, beyond its 600 000 ms buffer.
    early_payment: {
      signalMs: base.paidMs + 600001n,
      paymentId: hex(
        "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702afb",
      ),
    },
    other_intent: {
      intent: intentHash(orchestrator, 2n),
      paymentId: hex(
        "0x1602778d3521a01384c90b32caac50b99d4ccc6e7d0b007c180bf3f650702afa",
      ),
    },
  };
  const claims = {};
  const functions = [];
  for (const [name, overrides] of Object.entries(variants)) {
    const c = { ...base, ...overrides };
    const tokenAmount = 500n;
    const releaseAmount = 400n;
    const data = Buffer.concat([
      c.method,
      c.payee,
      word(c.fiat),
      c.currency,
      word(c.paidMs),
      c.paymentId,
      c.intent,
      word(tokenAmount),
      c.method,
      c.currency,
      c.payee,
      word(10n ** 18n),
      word(c.signalMs ?? c.paidMs - 120000n),
      word(600000n),
      word(0n),
      word(512n),
      word(0n),
    ]);
    if (data.length !== 544) throw new Error("ABI layout");
    const dataHash = keccak256(data);
    const signature = hex(
      await account.signTypedData({
        domain: {
          name: "UnifiedPaymentVerifier",
          version: "1",
          chainId,
          verifyingContract: verifier,
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
          intentHash: `0x${c.intent.toString("hex")}`,
          releaseAmount,
          dataHash,
        },
      }),
    );
    claims[name] = {
      intentHash: `0x${c.intent.toString("hex")}`,
      paymentId: `0x${c.paymentId.toString("hex")}`,
      payeeId: `0x${c.payee.toString("hex")}`,
      fiatAmount: String(c.fiat),
      paymentTimestampMs: String(c.paidMs),
      dataHash,
    };
    const padded = Buffer.concat([data, Buffer.alloc(CAPACITY - data.length)]);
    functions.push(`pub fn ${name}() -> PeerV4Payment {
    PeerV4Payment {
        chain_id: ${chainId},
        verifier_address: ${bytes(hex(verifier))},
        attestor_x: ${bytes(publicKey.subarray(1, 33))},
        attestor_y: ${bytes(publicKey.subarray(33, 65))},
        attestor_address: ${bytes(hex(account.address))},
        max_payment_age_ms: MAX_AGE_MS,
        intent_hash: ${bytes(c.intent)},
        release_amount: ${bytes(word(releaseAmount))},
        data_hash: ${bytes(hex(dataHash))},
        data: ${bytes(padded)},
        data_len: ${data.length},
        signature: ${bytes(signature)},
    }
}`);
  }
  const unformatted = `//! Generated by scripts/fixtures/generators/peer_v4.mjs; see fixtures/manifest.json. Do not edit.
//! Synthetic Peer V4 payment attestations signed with the public secp256k1
//! test scalar 1. That key is not a Peer witness; no payment took place.

use uc_adapter_peer_v4::PeerV4Payment;

/// The verifier time the attestations were made for, in Unix seconds; the
/// payments are 60 s earlier.
pub global NOW: u64 = ${now};
pub global PAID_AT: u64 = ${now - 60n};
/// The payment age that the fixtures accept, in milliseconds.
pub global MAX_AGE_MS: u64 = ${maxAgeMs};
/// The fiat amount of every attestation except \`other_amount\`.
pub global FIAT_AMOUNT: u128 = ${base.fiat};
/// The Peer intent of every attestation except \`other_intent\`.
pub global INTENT_HASH: Field = 0x${base.intent.toString("hex")};
/// The payment method, payee id and currency hashes of the base attestation.
pub global METHOD: [u8; 32] = ${bytes(base.method, "    ")};
pub global PAYEE_ID: [u8; 32] = ${bytes(base.payee, "    ")};
pub global CURRENCY: [u8; 32] = ${bytes(base.currency, "    ")};

${functions.join("\n\n")}
`;
  const fixture = formatNoir(unformatted);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const lock = "aztec/use-cases/package-lock.json";
  const record = {
    schema: "uc-fixture-v1",
    scheme: "peer_v4",
    use_case: "payment-settlement",
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/peer_v4.mjs",
        "--instance",
        values.instance,
        "--now",
        String(now),
        "--max-age-ms",
        String(maxAgeMs),
      ],
      cwd: "aztec/use-cases",
      library:
        "viem signTypedData (EIP-712) and keccak256, from aztec/use-cases dependencies",
    },
    inputs: {
      [generator]: sha256(await readFile(repository + generator)),
      [lock]: sha256(await readFile(repository + lock)),
    },
    key_provenance:
      "Public secp256k1 test scalar 1 (attestor address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf); not a Peer witness. Anyone can sign with it.",
    claims: {
      chainId,
      verifier,
      orchestrator,
      intentHash:
        "keccak256(orchestrator || counter) mod p, counter 1 (other_intent: 2)",
      attestations: claims,
    },
    notes: [
      "Variants are separately signed attestations for the wrong-term tests; other negative cases mutate a valid attestation in src/test.nr.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(`Wrote ${values.instance}/src/fixture.nr`);
}

await main();
