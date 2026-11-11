/** Strict prime-subgroup Ed25519 profile shared by QR/document consumers. */
import { ed25519 } from "@noble/curves/ed25519";
export type PointHint = { x_limbs: string[]; y_limbs: string[] };
const ELL = (1n << 252n) + 27742317777372353535851937790883648493n;
const integerLE = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
export function ed25519PointHint(bytes: Uint8Array, issuer = false): PointHint {
  if (bytes.length !== 32) throw Error("Ed25519 point must have 32 bytes");
  const point = ed25519.ExtendedPoint.fromHex(bytes);
  if (!Buffer.from(point.toRawBytes()).equals(Buffer.from(bytes)))
    throw Error("Noncanonical Ed25519 point");
  if (!point.isTorsionFree())
    throw Error("Ed25519 point outside prime subgroup");
  if (issuer && point.equals(ed25519.ExtendedPoint.ZERO))
    throw Error("Ed25519 issuer key is identity");
  const { x, y } = point.toAffine();
  const limbs = (n: bigint) =>
    [n & ((1n << 120n) - 1n), (n >> 120n) & ((1n << 120n) - 1n), n >> 240n].map(
      String,
    );
  return { x_limbs: limbs(x), y_limbs: limbs(y) };
}
/** Trust in publicKey must be established by caller; hints are constrained in Noir. */
export function importVerifiedEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
) {
  if (signature.length !== 64)
    throw Error("Ed25519 signature must have 64 bytes");
  if (integerLE(signature.subarray(32)) >= ELL)
    throw Error("Ed25519 scalar is not canonical");
  const public_hint = ed25519PointHint(publicKey, true);
  const signature_hint = ed25519PointHint(signature.subarray(0, 32));
  // Not node:crypto: OpenSSL 3.5 rejects a small-order R, which the strict profile accepts
  // (R and A are already canonical and in the prime subgroup here, so the equations agree).
  if (!ed25519.verify(signature, message, publicKey, { zip215: false }))
    throw Error("Ed25519 signature verification failed");
  return {
    public_key: [...publicKey],
    signature: [...signature],
    message: [...message],
    public_hint,
    signature_hint,
  };
}
