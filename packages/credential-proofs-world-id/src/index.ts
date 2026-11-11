import { keccak_256 } from "@noble/hashes/sha3";

export const FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export type Integer = string | bigint;
export function integer(value: unknown, limit = FR, name = "field"): bigint {
  if (
    typeof value !== "bigint" &&
    (typeof value !== "string" ||
      !/^(0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value))
  )
    throw new Error(
      `${name}: expected canonical unsigned integer string or bigint`,
    );
  let n: bigint;
  if (typeof value === "string") {
    // String-to-BigInt conversion is super-linear, so a 12 MB decimal
    // string blocks the event loop for seconds. A string with more significant
    // digits than limit - 1 is out of range anyway, so rejecting it before the
    // conversion keeps the accepted domain, including zero-padded hex.
    const hex = value.startsWith("0x"),
      digits = hex ? value.slice(2).replace(/^0+/, "") : value,
      max = (limit - 1n).toString(hex ? 16 : 10).length;
    if (limit < 1n || digits.length > max)
      throw new Error(`${name}: out of range`);
    n = BigInt(hex ? "0x" + (digits || "0") : value);
  } else n = value;
  if (n < 0n || n >= limit) throw new Error(`${name}: out of range`);
  return n;
}
export function fields(value: unknown, count: number): bigint[] {
  if (!Array.isArray(value) || value.length !== count)
    throw new Error(`Expected ${count} fields`);
  return value.map((x) => integer(x));
}
export function bytes32(value: Integer): Uint8Array {
  let n = integer(value, 1n << 256n);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(n & 255n);
    n >>= 8n;
  }
  return out;
}
export function hashToField(bytes: Uint8Array): bigint {
  // World ID / Semaphore convention: Keccak-256 interpreted BE, then >>8.
  return keccak_256(bytes)
    .slice(0, 31)
    .reduce((n, b) => (n << 8n) + BigInt(b), 0n);
}
export function externalNullifier(appId: string, action: string): bigint {
  const utf8 = new TextEncoder();
  const a = bytes32(hashToField(utf8.encode(appId))),
    b = utf8.encode(action);
  const data = new Uint8Array(a.length + b.length);
  data.set(a);
  data.set(b, a.length);
  return hashToField(data);
}
export type Context = readonly [
  Integer,
  Integer,
  Integer,
  Integer,
  Integer,
  Integer,
];
export const CONTEXT_DOMAIN = 0x574f524c445f49445f415a5445435f5631n;
/**
 * The signal is exactly 224 raw bytes: seven big-endian 32-byte words.
 * Hex text is only a transport representation: decode it before hashing.
 * Hashing its UTF-8 characters produces a different signal binding.
 * All six context fields bind.
 */
export function signalBytes(context: Context): Uint8Array {
  const words = [CONTEXT_DOMAIN, ...fields(context, 6)];
  const out = new Uint8Array(words.length * 32);
  words.forEach((x, i) => out.set(bytes32(x), i * 32));
  return out;
}
export function contextSignalHash(context: Context): bigint {
  return hashToField(signalBytes(context));
}

export type ClaimVersion = "world-id-3-semaphore" | "world-id-4-nullifier-v1";
export const INPUT_COUNTS: Readonly<Record<ClaimVersion, number>> =
  Object.freeze({
    "world-id-3-semaphore": 4,
    "world-id-4-nullifier-v1": 15,
  });
export interface RootPolicy {
  readonly root: Integer;
  readonly validUntil: Integer;
}
export interface SemaphorePolicy extends RootPolicy {
  readonly version: "world-id-3-semaphore";
  readonly externalNullifier: Integer;
}
export interface NullifierPolicy extends RootPolicy {
  readonly version: "world-id-4-nullifier-v1";
  readonly issuerSchemaId: Integer;
  readonly issuerKey: readonly [Integer, Integer];
  readonly oprfKey: readonly [Integer, Integer];
  readonly rpId: Integer;
  readonly action: Integer;
  readonly treeDepth: Integer;
  readonly minExpiry: Integer;
  readonly minGenesis: Integer;
}
/** Upstream BinaryMerkleRoot(30) accepts any leaf with root 0 for depths above 30. */
export const WORLD_ID4_MAX_TREE_DEPTH = 30n;
export type ClaimPolicy = SemaphorePolicy | NullifierPolicy;
export function publicInputs(version: ClaimVersion, value: unknown): bigint[] {
  if (!Object.hasOwn(INPUT_COUNTS, version))
    throw new Error("Unsupported World ID claim version");
  return fields(value, INPUT_COUNTS[version]);
}
/** Application checks only. This neither verifies a proof nor authenticates policy. */
export function checkClaim(
  policy: ClaimPolicy,
  value: unknown,
  context: Context,
  now: Integer,
): readonly bigint[] {
  const p = publicInputs(policy.version, value),
    c = fields(context, 6),
    time = integer(now, 1n << 64n);
  if (time > integer(policy.validUntil, 1n << 64n))
    throw new Error("Root policy expired");
  const eq = (a: bigint, b: Integer, label: string) => {
    if (a !== integer(b)) throw new Error(label);
  };
  const U64 = 1n << 64n;
  // c[0..2] (chain, version, consumer) come from the deployed contract and
  // cannot be checked here; c[3] and c[5] must match the policy as the
  // contract-equivalent Noir checks require.
  if (policy.version === "world-id-3-semaphore") {
    eq(p[0], policy.root, "Unapproved root");
    eq(p[3], policy.externalNullifier, "Wrong external nullifier");
    eq(p[2], contextSignalHash(context), "Wrong signal binding");
    eq(c[3], policy.externalNullifier, "Context action mismatch");
  } else if (policy.version === "world-id-4-nullifier-v1") {
    // Policy domain, as NullifierPolicy::from_fields and validate in Noir.
    const root = integer(policy.root, FR, "root"),
      depth = integer(policy.treeDepth, U64, "treeDepth"),
      action = integer(policy.action, FR, "action"),
      minExpiry = integer(policy.minExpiry, U64, "minExpiry"),
      minGenesis = integer(policy.minGenesis, U64, "minGenesis");
    if (root === 0n) throw new Error("Zero root");
    if (action >= 1n << 248n) throw new Error("Uniqueness action range");
    if (depth > WORLD_ID4_MAX_TREE_DEPTH) throw new Error("Tree depth range");
    if (
      integer(policy.issuerKey[0]) === 0n ||
      integer(policy.issuerKey[1]) === 0n
    )
      throw new Error("Unregistered issuer");
    eq(p[1], integer(policy.issuerSchemaId, U64), "Wrong issuer");
    eq(p[2], policy.issuerKey[0], "Wrong issuer key");
    eq(p[3], policy.issuerKey[1], "Wrong issuer key");
    if (p[4] >= U64) throw new Error("Expiration range");
    // Strict: an upstream request that leaves expires_at_min at its default
    // (the request time) is rejected once the anchor time passes it.
    if (p[4] < time || p[4] < minExpiry)
      throw new Error("Credential expiration bound too old");
    // Upstream LessEqThan(64) also accepts genesis_issued_at_min values in
    // [FR - 2^64 + g + 1, FR); only a u64 value makes the comparison sound.
    if (p[5] >= U64) throw new Error("Genesis range");
    if (p[5] < minGenesis) throw new Error("Credential genesis bound too old");
    eq(p[6], root, "Unapproved root");
    eq(p[7], depth, "Wrong tree depth");
    eq(p[8], integer(policy.rpId, U64), "Wrong relying party");
    eq(p[9], action, "Wrong action");
    eq(p[10], policy.oprfKey[0], "Wrong OPRF key");
    eq(p[11], policy.oprfKey[1], "Wrong OPRF key");
    eq(p[12], contextSignalHash(context), "Wrong signal binding");
    eq(c[3], action, "Context action mismatch");
    eq(p[13], c[5], "Wrong nonce");
    eq(p[14], 0n, "Session proofs require a separate policy");
  } else throw new Error("Unsupported World ID claim version");
  return Object.freeze(p);
}
/** Nullifier preimage for a contract-scoped Poseidon2 hash. Never include root,
 * beneficiary or nonce: refreshing a root/context must not enable a second use.
 * World ID 4 also excludes issuer_schema_id: the upstream nullifier does not
 * depend on the issuer, so a multi-issuer policy must not allow one claim per
 * issuer. */
export function nullifierFields(
  policy: SemaphorePolicy | NullifierPolicy,
  inputs: unknown,
): readonly bigint[] {
  if (
    policy.version !== "world-id-3-semaphore" &&
    policy.version !== "world-id-4-nullifier-v1"
  )
    throw new Error("This claim has no supported uniqueness nullifier");
  const p = publicInputs(policy.version, inputs);
  return policy.version === "world-id-3-semaphore"
    ? [CONTEXT_DOMAIN + 1n, 3n, p[3], p[1]]
    : [CONTEXT_DOMAIN + 1n, 4n, p[8], p[9], p[0]];
}
