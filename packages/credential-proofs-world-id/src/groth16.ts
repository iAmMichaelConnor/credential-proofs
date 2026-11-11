import { bn254 } from "@noble/curves/bn254";
import {
  prepareRuntimeKey,
  prepareRuntimeHints68,
  type RuntimeOptions,
} from "groth16-verifier-hints";
import {
  fields,
  integer,
  publicInputs,
  type ClaimVersion,
  type Context,
} from "./index.js";
export { prepareRuntimeKey } from "groth16-verifier-hints";
export function worldIdPrivateArguments(
  hints: Awaited<ReturnType<typeof prepareRuntimeHints68>>,
) {
  return {
    key: hints.flatKey,
    proof: hints.proof,
    hints: [
      ...hints.capsules.private[0].values,
      ...hints.capsules.private[1].values,
    ],
    public_inputs: hints.publicInputs,
  };
}
const F = bn254.fields.Fp,
  Q = F.ORDER;
const mod = (x: bigint) => F.create(x);
function sqrt(x: bigint): bigint {
  // Match the exact upstream exponent/root choice, not an arbitrary sqrt sign.
  const y = F.pow(x, (Q + 1n) / 4n);
  if (F.sqr(y) !== x) throw new Error("Invalid compressed point");
  return y;
}
function g1(c: bigint): [bigint, bigint] {
  if (c === 0n) return [0n, 0n];
  const x = c >> 1n;
  integer(x, Q);
  const y = sqrt(mod(x * x * x + 3n));
  return [x, c & 1n ? mod(-y) : y];
}
/** World ID Solidity compression, not SEC1. G2 words arrive imaginary first.
 * Source: https://github.com/worldcoin/world-id-protocol/blob/46f6b43d231780e4fc0b5030bd71e846664532d1/contracts/src/core/Verifier.sol
 * Arithmetic uses Noble; this codec does not replace subgroup/pairing checks. */
export function decompressWorldIdProof(value: unknown) {
  if (!Array.isArray(value) || value.length !== 4)
    throw new Error("Expected four compressed proof words");
  const c = value.map((x) => integer(x, 1n << 256n));
  const a = g1(c[0]),
    z = g1(c[3]);
  const c0 = c[2],
    c1 = c[1];
  let x0 = 0n,
    x1 = 0n,
    y0 = 0n,
    y1 = 0n;
  if (c0 !== 0n || c1 !== 0n) {
    x0 = integer(c0 >> 2n, Q);
    x1 = integer(c1, Q);
    // For i^2=-1, y^2=x^3+3/(9+i). Thus Re(b)=27/82, Im(b)=-3/82.
    // If y^2=r+s*i, d^2=r^2+s^2, y0^2=(r+d)/2, y1=s/(2*y0).
    // Match upstream's hint/sign choice and rejection when y0=0: invert_Fp
    // also rejects zero. This is its transport domain, not a generic Fp2 sqrt.
    const inv82 = F.inv(82n),
      r = mod(x0 * x0 * x0 - 3n * x0 * x1 * x1 + 27n * inv82);
    const s = mod(3n * x0 * x0 * x1 - x1 * x1 * x1 - 3n * inv82);
    let d = sqrt(mod(r * r + s * s));
    if (c0 & 2n) d = mod(-d);
    y0 = sqrt(mod((r + d) * F.inv(2n)));
    y1 = mod(s * F.inv(mod(2n * y0)));
    if (mod(y0 * y0 - y1 * y1) !== r || mod(2n * y0 * y1) !== s)
      throw new Error("Invalid G2 square root");
    if (c0 & 1n) {
      y0 = mod(-y0);
      y1 = mod(-y1);
    }
  }
  return {
    protocol: "groth16",
    curve: "bn128",
    pi_a: a,
    pi_b: [
      [x0, x1],
      [y0, y1],
    ],
    pi_c: z,
  };
}
export function fromSolidityProof(value: unknown) {
  if (!Array.isArray(value) || value.length !== 8)
    throw new Error("Expected eight Solidity proof coordinates");
  const p = value.map((x) => integer(x, Q));
  return {
    protocol: "groth16",
    curve: "bn128",
    pi_a: p.slice(0, 2),
    pi_b: [
      [p[3], p[2]],
      [p[5], p[4]],
    ],
    pi_c: p.slice(6, 8),
  };
}
export async function prepareWorldIdGroth16(
  request: {
    version: ClaimVersion;
    key: unknown;
    authorizedKeyHash: string | bigint;
    proof: unknown;
    publicInputs: unknown;
    context: Context;
  },
  options: RuntimeOptions = {},
) {
  if (
    request.version !== "world-id-3-semaphore" &&
    request.version !== "world-id-4-nullifier-v1"
  )
    throw new Error("Unsupported Groth16 application version");
  const inputs = publicInputs(request.version, request.publicInputs),
    key = prepareRuntimeKey(request.key);
  if (
    key.inputCount !== inputs.length ||
    key.keyHash !== integer(request.authorizedKeyHash)
  )
    throw new Error("Unauthorized World ID verification key");
  return prepareRuntimeHints68(
    {
      key,
      proof: request.proof,
      publicInputs: inputs,
      application: fields(request.context, 6),
    },
    options,
  );
}
