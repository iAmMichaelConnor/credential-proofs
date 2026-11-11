/** Reusable Reclaim EIP191 envelope checks; application/registry/TLS trust remains explicit policy. */
import { keccak256, stringToHex, recoverMessageAddress, type Hex } from "viem";
export interface ReclaimEnvelope {
  provider: string;
  parameters: string;
  context: string;
  identifier: Hex;
  owner: Hex;
  timestampS: number;
  epoch: number;
  signature: Hex;
}
export function reclaimIdentifier(
  provider: string,
  parameters: string,
  canonicalContext: string,
): Hex {
  return keccak256(
    stringToHex(provider + "\n" + parameters + "\n" + canonicalContext),
  );
}
export function reclaimSignData(
  claim: Pick<ReclaimEnvelope, "identifier" | "owner" | "timestampS" | "epoch">,
): string {
  if (
    !/^0x[0-9a-f]{64}$/.test(claim.identifier) ||
    !/^0x[0-9a-f]{40}$/.test(claim.owner)
  )
    throw Error("noncanonical Reclaim identifier/owner");
  for (const value of [claim.timestampS, claim.epoch])
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
      throw Error("Reclaim integer outside u32");
  return (
    claim.identifier +
    "\n" +
    claim.owner +
    "\n" +
    claim.timestampS +
    "\n" +
    claim.epoch
  );
}
/** Context must already be canonical JSON chosen by the relying application. */
export async function verifyReclaimEnvelope(
  claim: ReclaimEnvelope,
  trustedAttestor: Hex,
): Promise<void> {
  if (
    !/^0x[0-9a-fA-F]{130}$/.test(claim.signature) ||
    ![0, 1, 27, 28].includes(Number.parseInt(claim.signature.slice(-2), 16))
  )
    throw Error("invalid Reclaim wire signature");
  if (!/^0x[0-9a-fA-F]{40}$/.test(trustedAttestor))
    throw Error("invalid trusted Reclaim attestor");
  if (
    reclaimIdentifier(claim.provider, claim.parameters, claim.context) !==
    claim.identifier
  )
    throw Error("Reclaim identifier mismatch");
  const recovered = await recoverMessageAddress({
    message: reclaimSignData(claim),
    signature: claim.signature,
  });
  if (recovered.toLowerCase() !== trustedAttestor.toLowerCase())
    throw Error("Reclaim signature attestor mismatch");
}
