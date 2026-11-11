import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import type { JSONPOD } from "@pcd/pod";
import { writeToml } from "./toml.js";

// Use @pcd/pod's documented CommonJS entry: its 0.5.1 ESM graph is incompatible
// with blakejs' CommonJS named exports under current Node ESM resolution.
const require = createRequire(import.meta.url);
const { POD, decodePublicKey, decodeSignature, deriveSignerPublicKey } =
  require("@pcd/pod") as typeof import("@pcd/pod");

const MAX_DEPTH = 8;

export type PodWitness = {
  content_id: string;
  name_hash: string;
  value_hash: string;
  depth: number;
  indices: boolean[];
  siblings: string[];
  issuer: { x: string; y: string };
  signature: { rx: string; ry: string; s: string };
};

export function podToCircuitWitness(
  input: unknown,
  entryName: string,
): PodWitness {
  const pod = POD.fromJSON(input as JSONPOD);
  if (!pod.verifySignature())
    throw new Error("POD signature verification failed");
  const signals = pod.content.generateEntryCircuitSignals(entryName);
  const proof = signals.proof;
  if (proof.siblings.length < 1)
    throw new Error("POD membership proof is missing its value leaf");
  const upperSiblings = proof.siblings.slice(1);
  if (upperSiblings.length > MAX_DEPTH)
    throw new Error(
      `POD entry depth ${upperSiblings.length} exceeds circuit capacity ${MAX_DEPTH}`,
    );
  const key = decodePublicKey(pod.signerPublicKey);
  const signature = decodeSignature(pod.signature);
  return {
    content_id: pod.contentID.toString(),
    name_hash: signals.nameHash.toString(),
    value_hash: signals.valueHash.toString(),
    depth: upperSiblings.length,
    indices: Array.from(
      { length: MAX_DEPTH },
      (_, i) => Math.floor(proof.index / 2 ** (i + 1)) % 2 === 1,
    ),
    siblings: [
      ...upperSiblings.map(String),
      ...Array(MAX_DEPTH - upperSiblings.length).fill("0"),
    ],
    issuer: { x: key[0].toString(), y: key[1].toString() },
    signature: {
      rx: signature.R8[0].toString(),
      ry: signature.R8[1].toString(),
      s: signature.S.toString(),
    },
  };
}

function toml(w: PodWitness) {
  return {
    content_id: w.content_id,
    name_hash: w.name_hash,
    value_hash: w.value_hash,
    depth: w.depth,
    indices: w.indices,
    siblings: w.siblings,
    issuer: w.issuer,
    signature: w.signature,
  };
}

export async function importPodFile(
  inputPath: string,
  entryName: string,
  outputPath: string,
): Promise<void> {
  const json = JSON.parse(await readFile(inputPath, "utf8")) as unknown;
  await writeToml(outputPath, toml(podToCircuitWitness(json, entryName)));
}

// Holder approval POD. The holder signs a POD with exactly these
// three entries; noir/zupass `assert_holder_approval` recomputes
// its content ID. POD names allow only letters, digits and underscores.
export const HOLDER_APPROVAL_ENTRIES = {
  account: "_aztec_auth_v1_account",
  action: "_aztec_auth_v1_action",
  expires: "_aztec_auth_v1_expires",
} as const;

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const INT_MAX = (1n << 63n) - 1n;

export type HolderApproval = {
  /** The Aztec account address, as a field. */
  account: bigint;
  /** The account's action hash. Holder software computes it from the calls it shows. */
  action: bigint;
  /** Unix seconds; the transaction must be included strictly before it. */
  expires: bigint;
};

export type HolderApprovalWitness = {
  account: string;
  action: string;
  expires: string;
  content_id: string;
  holder: { x: string; y: string };
  signature: { rx: string; ry: string; s: string };
};

function fieldValue(name: string, value: bigint): bigint {
  if (typeof value !== "bigint" || value < 0n || value >= FIELD_MODULUS)
    throw new Error(`${name} must be a field element`);
  return value;
}

/** The POD entries of a holder approval. */
export function holderApprovalEntries(approval: HolderApproval) {
  const expires = approval.expires;
  if (typeof expires !== "bigint" || expires < 1n || expires > INT_MAX)
    throw new Error("expires must be 1 to 2^63 - 1 Unix seconds");
  return {
    [HOLDER_APPROVAL_ENTRIES.account]: {
      type: "cryptographic" as const,
      value: fieldValue("account", approval.account),
    },
    [HOLDER_APPROVAL_ENTRIES.action]: {
      type: "cryptographic" as const,
      value: fieldValue("action", approval.action),
    },
    [HOLDER_APPROVAL_ENTRIES.expires]: { type: "int" as const, value: expires },
  };
}

/**
 * Sign a holder approval POD with the holder's EdDSA-Poseidon private key. Holder
 * software must compute `action` itself from the account, chain, version and
 * payload that it shows the holder, and must not sign a POD with these entry
 * names on request of any other party.
 */
export function signHolderApproval(
  approval: HolderApproval,
  holderPrivateKey: string,
): JSONPOD {
  return POD.sign(holderApprovalEntries(approval), holderPrivateKey).toJSON();
}

/**
 * Verify a holder approval POD (exactly the three entries, their types, the signature,
 * and optionally the expected signer) and convert it to the Noir witness.
 */
export function holderApprovalWitness(
  input: unknown,
  expectedHolder?: string,
): HolderApprovalWitness {
  const pod = POD.fromJSON(input as JSONPOD);
  if (!pod.verifySignature())
    throw new Error("holder approval signature verification failed");
  if (expectedHolder !== undefined && pod.signerPublicKey !== expectedHolder)
    throw new Error("holder approval is signed by another key");
  const entries = pod.content.asEntries();
  const names = Object.keys(entries).sort();
  const expected = Object.values(HOLDER_APPROVAL_ENTRIES).slice().sort();
  if (
    names.length !== expected.length ||
    names.some((name, i) => name !== expected[i])
  )
    throw new Error(
      "holder approval must have exactly the account, action and expires entries",
    );
  const account = entries[HOLDER_APPROVAL_ENTRIES.account];
  const action = entries[HOLDER_APPROVAL_ENTRIES.action];
  const expires = entries[HOLDER_APPROVAL_ENTRIES.expires];
  if (
    account.type !== "cryptographic" ||
    action.type !== "cryptographic" ||
    expires.type !== "int"
  )
    throw new Error(
      "holder approval entry types must be cryptographic, cryptographic and int",
    );
  const approval = {
    account: account.value,
    action: action.value,
    expires: expires.value,
  };
  holderApprovalEntries(approval); // enforces the expires bounds
  const key = decodePublicKey(pod.signerPublicKey);
  const signature = decodeSignature(pod.signature);
  return {
    account: approval.account.toString(),
    action: approval.action.toString(),
    expires: approval.expires.toString(),
    content_id: pod.contentID.toString(),
    holder: { x: key[0].toString(), y: key[1].toString() },
    signature: {
      rx: signature.R8[0].toString(),
      ry: signature.R8[1].toString(),
      s: signature.S.toString(),
    },
  };
}

/** The EdDSA-Poseidon public key (POD encoding) of a private key. */
export function holderPublicKey(holderPrivateKey: string): string {
  return deriveSignerPublicKey(holderPrivateKey);
}

// Holder login POD. For a login link the holder signs a POD with
// exactly these two entries; noir/zupass `assert_holder_login`
// recomputes its content ID. The challenge already commits to the chain, the
// linking contract, the caller and the round, and the relying party's max_age
// measures freshness from the signed issue time, so the POD needs no account,
// action or expiry entry.
export const HOLDER_LOGIN_ENTRIES = {
  challenge: "_aztec_link_v1_challenge",
  issuedAt: "_aztec_link_v1_issued_at",
} as const;

export type HolderLogin = {
  /** The link challenge. Holder software computes it from the chain, contract, caller and round that it shows. */
  challenge: bigint;
  /** Unix seconds; the time of the login that the holder states. */
  issuedAt: bigint;
};

export type HolderLoginWitness = {
  challenge: string;
  issued_at: string;
  content_id: string;
  holder: { x: string; y: string };
  signature: { rx: string; ry: string; s: string };
};

/** The POD entries of a holder login. */
export function holderLoginEntries(login: HolderLogin) {
  const issuedAt = login.issuedAt;
  if (typeof issuedAt !== "bigint" || issuedAt < 1n || issuedAt > INT_MAX)
    throw new Error("issuedAt must be 1 to 2^63 - 1 Unix seconds");
  return {
    [HOLDER_LOGIN_ENTRIES.challenge]: {
      type: "cryptographic" as const,
      value: fieldValue("challenge", login.challenge),
    },
    [HOLDER_LOGIN_ENTRIES.issuedAt]: { type: "int" as const, value: issuedAt },
  };
}

/**
 * Sign a holder login POD with the holder's EdDSA-Poseidon private key. Holder
 * software must compute `challenge` itself from the chain, version, linking
 * contract, caller and round that it shows the holder, and must not sign a POD
 * with these entry names on request of any other party.
 */
export function signHolderLogin(
  login: HolderLogin,
  holderPrivateKey: string,
): JSONPOD {
  return POD.sign(holderLoginEntries(login), holderPrivateKey).toJSON();
}

/**
 * Verify a holder login POD (exactly the two entries, their types, the signature,
 * and optionally the expected signer) and convert it to the Noir witness.
 */
export function holderLoginWitness(
  input: unknown,
  expectedHolder?: string,
): HolderLoginWitness {
  const pod = POD.fromJSON(input as JSONPOD);
  if (!pod.verifySignature())
    throw new Error("holder login signature verification failed");
  if (expectedHolder !== undefined && pod.signerPublicKey !== expectedHolder)
    throw new Error("holder login is signed by another key");
  const entries = pod.content.asEntries();
  const names = Object.keys(entries).sort();
  const expected = Object.values(HOLDER_LOGIN_ENTRIES).slice().sort();
  if (
    names.length !== expected.length ||
    names.some((name, i) => name !== expected[i])
  )
    throw new Error(
      "holder login must have exactly the challenge and issued_at entries",
    );
  const challenge = entries[HOLDER_LOGIN_ENTRIES.challenge];
  const issuedAt = entries[HOLDER_LOGIN_ENTRIES.issuedAt];
  if (challenge.type !== "cryptographic" || issuedAt.type !== "int")
    throw new Error("holder login entry types must be cryptographic and int");
  const login = { challenge: challenge.value, issuedAt: issuedAt.value };
  holderLoginEntries(login); // enforces the issuedAt bounds
  const key = decodePublicKey(pod.signerPublicKey);
  const signature = decodeSignature(pod.signature);
  return {
    challenge: login.challenge.toString(),
    issued_at: login.issuedAt.toString(),
    content_id: pod.contentID.toString(),
    holder: { x: key[0].toString(), y: key[1].toString() },
    signature: {
      rx: signature.R8[0].toString(),
      ry: signature.R8[1].toString(),
      s: signature.S.toString(),
    },
  };
}
