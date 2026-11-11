// Original official historical attestor fixture, generic envelope only.
import { readFile } from "node:fs/promises";
import {
  recoverPublicKey,
  hashMessage,
  hexToBytes,
  keccak256,
  toBytes,
} from "viem";
import { verifyReclaimEnvelope, reclaimSignData } from "credential-proofs-inputs/reclaim";

import { writeToml } from "credential-proofs-inputs/toml";

const data = JSON.parse(
  await readFile(
    new URL(
      "../../fixtures/material/reclaim/provider-test/steam-example.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const c = { ...data.claimData, signature: data.signatures[0] };
const attestor = "0x244897572368eadf65bfbc5aec98d8e5443a9072";
await verifyReclaimEnvelope(c, attestor);
const key = hexToBytes(
  await recoverPublicKey({
    hash: hashMessage(reclaimSignData(c)),
    signature: c.signature,
  }),
);
const padded = (v, n) => {
  const a = [...Buffer.from(v)];
  if (a.length > n) throw Error("example input bound");
  return [...a, ...Array(n - a.length).fill(0)];
};
await writeToml(
  new URL("../../target/kat/reclaim/Prover.toml", import.meta.url).pathname,
  {
    claim: {
      provider: padded(c.provider, 8),
      provider_len: Buffer.byteLength(c.provider),
      parameters: padded(c.parameters, 512),
      parameters_len: Buffer.byteLength(c.parameters),
      context: padded(c.context, 256),
      context_len: Buffer.byteLength(c.context),
      owner: [...Buffer.from(c.owner)],
      timestamp_s: c.timestampS,
      epoch: c.epoch,
      identifier: [...hexToBytes(c.identifier)],
      signature: [...hexToBytes(c.signature)],
    },
    policy: {
      provider: padded(c.provider, 8),
      provider_len: Buffer.byteLength(c.provider),
      parameters_hash: [...hexToBytes(keccak256(toBytes(c.parameters)))],
      attestor_x: [...key.slice(1, 33)],
      attestor_y: [...key.slice(33)],
      attestor_address: [...hexToBytes(attestor)],
      expected_epoch: c.epoch,
      max_age_seconds: 60,
    },
    expected_context: padded(c.context, 256),
    expected_context_len: Buffer.byteLength(c.context),
    now: c.timestampS,
  },
);
