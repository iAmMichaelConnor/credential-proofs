import { createHash, verify, X509Certificate } from "node:crypto";
import { rsaKeyToCircuit } from "./oidc.js";
export const JPKI_AUTH_CA03_SHA256 =
  "64114f29620c24ed2631d46476a040e7ee740d956089c00b036a6a8118c322b5";
export const JPKI_AUTH_CA02_SHA256 =
  "0d98de47fc11b7f67126874b7028b6026a803d2638d6edfe53176953961fade6";
export interface JpkiCapture {
  root: Uint8Array;
  certificate: Uint8Array;
  responder?: Uint8Array;
  ocsp: Uint8Array;
  holderSignature: Uint8Array;
  account: string;
  action: string;
  session: string;
  now: number;
  maxOcspAge?: number;
  localTestRoot?: boolean;
}
function bytes32(v: string): Buffer {
  if (!/^(?:0x)?[0-9a-f]{64}$/.test(v))
    throw Error("expected canonical lowercase 32-byte hex");
  return Buffer.from(v.replace(/^0x/, ""), "hex");
}
export function jpkiChallenge(
  account: string,
  action: string,
  session: string,
): Buffer {
  return Buffer.concat([
    Buffer.from("MIKE_JPKI_CARD_AUTH_V1__________"),
    bytes32(account),
    bytes32(action),
    bytes32(session),
  ]);
}
export function jpkiCardDigestInfo(
  account: string,
  action: string,
  session: string,
): Buffer {
  return Buffer.concat([
    Buffer.from("3031300d060960864801650304020105000420", "hex"),
    createHash("sha256")
      .update(jpkiChallenge(account, action, session))
      .digest(),
  ]);
}
function hash(v: Uint8Array): string {
  return createHash("sha256").update(v).digest("hex");
}
function array(v: Uint8Array): string {
  return `[${[...v].join(", ")}]`;
}
function bounded(v: Uint8Array, max: number): string {
  if (v.length > max) throw Error("JPKI DER input exceeds documented capacity");
  return `{ storage = [${[...v, ...Array<number>(max - v.length).fill(0)].join(", ")}], len = ${v.length} }`;
}
function rsa(c: X509Certificate): string {
  return (
    "[" +
    rsaKeyToCircuit(c.publicKey.export({ format: "jwk" }))
      .redc_params_limbs.map((v) => JSON.stringify(v))
      .join(", ") +
    "]"
  );
}
/** Import only. Complete purpose and signed OCSP validation occurs in Noir.
 * No private key, card PIN, provider login or network operation. */
export function jpkiToml(i: JpkiCapture): string {
  const root = new X509Certificate(i.root),
    leaf = new X509Certificate(i.certificate),
    rootHash = hash(root.raw);
  if (
    !i.localTestRoot &&
    rootHash !== JPKI_AUTH_CA03_SHA256 &&
    rootHash !== JPKI_AUTH_CA02_SHA256
  )
    throw Error("unapproved JPKI root");
  if (!root.ca || !root.checkIssued(root) || !root.verify(root.publicKey))
    throw Error("invalid root certificate");
  if (leaf.ca || !leaf.checkIssued(root) || !leaf.verify(root.publicKey))
    throw Error("holder certificate chain rejected");
  if (!Number.isSafeInteger(i.now) || i.now < 0)
    throw Error("invalid JPKI evaluation time");
  const age = i.maxOcspAge ?? 300;
  if (!Number.isSafeInteger(age) || age < 1 || age > 86400)
    throw Error("invalid OCSP freshness policy");
  const signer = i.responder?.length ? new X509Certificate(i.responder) : root;
  if (
    signer !== root &&
    (!signer.checkIssued(root) || !signer.verify(root.publicKey))
  )
    throw Error("OCSP signer chain rejected");
  for (const c of [root, leaf, signer])
    if (
      i.now * 1000 < Date.parse(c.validFrom) ||
      i.now * 1000 >= Date.parse(c.validTo)
    )
      throw Error("certificate outside validity");
  if (
    i.holderSignature.length !== 256 ||
    !verify(
      "sha256",
      jpkiChallenge(i.account, i.action, i.session),
      leaf.publicKey,
      i.holderSignature,
    )
  )
    throw Error("holder challenge signature rejected");
  if (!i.ocsp.length) throw Error("signed OCSP response required");
  const spki = leaf.publicKey.export({ format: "der", type: "spki" });
  return [
    `now = ${i.now}`,
    `account = ${array(bytes32(i.account))}`,
    `action = ${array(bytes32(i.action))}`,
    `session = ${array(bytes32(i.session))}`,
    "[policy]",
    `anchor_class = ${i.localTestRoot ? 1 : 0}`,
    `root_sha256 = ${array(Buffer.from(rootHash, "hex"))}`,
    `holder_spki_sha256 = ${array(Buffer.from(hash(spki), "hex"))}`,
    `max_ocsp_age = ${age}`,
    "[input]",
    `root = ${bounded(root.raw, 2048)}`,
    `certificate = ${bounded(leaf.raw, 2048)}`,
    `responder = ${bounded(i.responder?.length ? signer.raw : Buffer.alloc(0), 2048)}`,
    `ocsp = ${bounded(i.ocsp, 4096)}`,
    `holder_signature = ${array(i.holderSignature)}`,
    `root_redc = ${rsa(root)}`,
    `holder_redc = ${rsa(leaf)}`,
    `responder_redc = ${rsa(signer)}`,
    "",
  ].join("\n");
}
