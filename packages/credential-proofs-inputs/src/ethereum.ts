import { readFile } from "node:fs/promises";
import { privateKeyToAccount } from "viem/accounts";
import {
  bytesFromHex,
  paddedBytes,
  writeToml,
  type TomlDocument,
} from "./toml.js";

const PERSONAL_MAX = 256;
const SIWE_MAX = 512;
const SECP256K1_ORDER =
  0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffe_baaedce6_af48a03b_bfd25e8c_d0364141n;

function accountFromKey(privateKey: string) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey))
    throw new Error("expected a 32-byte 0x-prefixed secp256k1 private key");
  const scalar = BigInt(privateKey);
  if (scalar < 1n || scalar >= SECP256K1_ORDER)
    throw new Error("private key must be a canonical nonzero secp256k1 scalar");
  return privateKeyToAccount(privateKey as `0x${string}`);
}

function publicKeyCoordinates(publicKey: string): {
  public_key_x: number[];
  public_key_y: number[];
} {
  const bytes = bytesFromHex(publicKey, 65);
  if (bytes[0] !== 4)
    throw new Error("expected uncompressed secp256k1 public key");
  return {
    public_key_x: Array.from(bytes.subarray(1, 33)),
    public_key_y: Array.from(bytes.subarray(33, 65)),
  };
}

function signatureBytes(signature: string): number[] {
  const bytes = bytesFromHex(signature, 65);
  // The Noir library consumes canonical r || s; EIP-191's recovery byte is not
  // part of its signature equation. viem signs with low-s normalization.
  return Array.from(bytes.subarray(0, 64));
}

function addressBytes(address: string): number[] {
  return Array.from(bytesFromHex(address, 20));
}

export async function createPersonalSign(
  message: string,
  privateKey: string,
): Promise<TomlDocument> {
  const bytes = Buffer.from(message, "utf8");
  if (bytes.length > PERSONAL_MAX)
    throw new Error(`personal-sign message exceeds ${PERSONAL_MAX} bytes`);
  const account = accountFromKey(privateKey);
  const signature = await account.signMessage({ message: { raw: bytes } });
  return {
    message: paddedBytes(bytes, PERSONAL_MAX),
    message_len: bytes.length,
    ...publicKeyCoordinates(account.publicKey),
    signature: signatureBytes(signature),
    expected_address: addressBytes(account.address),
  };
}

export type SiweContext = {
  /** RFC 3986 authority as visible ASCII (0x21..0x7e); use punycode for IDNs. */
  domain: string;
  /** RFC 3986 URI as visible ASCII (0x21..0x7e). */
  uri: string;
  chainId: bigint;
  nonce: string;
  /**
   * The circuit requires issuedAt <= currentTime < expirationTime. Accounts
   * set currentTime to the anchor block time, which lags wall-clock time. Set
   * issuedAt to the anchor block time or earlier, or the message is rejected
   * until a newer block is anchored.
   */
  issuedAt: string;
  expirationTime: string;
  currentTime: string;
};

// Same byte rule as the Noir `siwe` builder: 1..128 bytes, each 0x21..0x7e.
const SIWE_VISIBLE_ASCII = /^[\x21-\x7e]{1,128}$/;

function timestamp(value: string): string {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
    new Date(value).toISOString().replace(".000Z", "Z") !== value
  ) {
    throw new Error(
      `SIWE timestamp must be a real UTC YYYY-MM-DDTHH:mm:ssZ value: ${value}`,
    );
  }
  return value;
}

export function buildSiweMessage(
  address: string,
  context: SiweContext,
): string {
  if (!SIWE_VISIBLE_ASCII.test(context.domain))
    throw new Error(
      "SIWE domain must be 1..128 visible ASCII bytes (0x21..0x7e)",
    );
  if (!SIWE_VISIBLE_ASCII.test(context.uri))
    throw new Error("SIWE URI must be 1..128 visible ASCII bytes (0x21..0x7e)");
  if (!/^[A-Za-z0-9]{8,32}$/.test(context.nonce))
    throw new Error("SIWE nonce must be 8..32 ASCII alphanumeric characters");
  if (context.chainId < 0n || context.chainId > 0xffff_ffff_ffff_ffffn)
    throw new Error("SIWE chain ID must fit u64");
  const issuedAt = timestamp(context.issuedAt);
  const expirationTime = timestamp(context.expirationTime);
  const currentTime = timestamp(context.currentTime);
  if (issuedAt > currentTime || expirationTime <= currentTime)
    throw new Error("SIWE issue/expiry window does not contain currentTime");
  return `${context.domain} wants you to sign in with your Ethereum account:\n${address}\n\n\nURI: ${context.uri}\nVersion: 1\nChain ID: ${context.chainId}\nNonce: ${context.nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
}

export async function createSiwe(
  privateKey: string,
  context: SiweContext,
): Promise<TomlDocument> {
  const account = accountFromKey(privateKey);
  const message = buildSiweMessage(account.address, context);
  const messageBytes = Buffer.from(message, "utf8");
  if (messageBytes.length > SIWE_MAX)
    throw new Error(`canonical SIWE message exceeds ${SIWE_MAX} bytes`);
  const signature = await account.signMessage({ message });
  return {
    address: addressBytes(account.address),
    ...publicKeyCoordinates(account.publicKey),
    signature: signatureBytes(signature),
    submitted_message: paddedBytes(messageBytes, SIWE_MAX),
    submitted_len: messageBytes.length,
    context: {
      domain: paddedBytes(Buffer.from(context.domain), 128),
      domain_len: Buffer.byteLength(context.domain),
      uri: paddedBytes(Buffer.from(context.uri), 128),
      uri_len: Buffer.byteLength(context.uri),
      chain_id: context.chainId,
      nonce: paddedBytes(Buffer.from(context.nonce), 32),
      nonce_len: context.nonce.length,
      issued_at: Array.from(Buffer.from(timestamp(context.issuedAt))),
      expiration_time: Array.from(
        Buffer.from(timestamp(context.expirationTime)),
      ),
      current_time: Array.from(Buffer.from(timestamp(context.currentTime))),
    },
  };
}

export function createSecretKeyWitness(privateKey: string): TomlDocument {
  const account = accountFromKey(privateKey);
  return {
    secret_key: Array.from(bytesFromHex(privateKey, 32)),
    expected_address: addressBytes(account.address),
  };
}

export async function createSecretKeyFromEnvironment(
  outputPath: string,
): Promise<void> {
  const privateKey = process.env.AUTH_ETHEREUM_PRIVATE_KEY;
  if (!privateKey)
    throw new Error(
      "set AUTH_ETHEREUM_PRIVATE_KEY in the environment; do not pass or log a private key on the command line",
    );
  await writeToml(outputPath, createSecretKeyWitness(privateKey));
}

export async function createPersonalSignFromFile(
  messagePath: string,
  outputPath: string,
): Promise<void> {
  const privateKey = process.env.AUTH_ETHEREUM_PRIVATE_KEY;
  if (!privateKey)
    throw new Error(
      "set AUTH_ETHEREUM_PRIVATE_KEY in the environment; do not pass or log a private key on the command line",
    );
  const message = await readFile(messagePath, "utf8");
  await writeToml(outputPath, await createPersonalSign(message, privateKey));
}

export async function createSiweFromContextFile(
  contextPath: string,
  outputPath: string,
): Promise<void> {
  const privateKey = process.env.AUTH_ETHEREUM_PRIVATE_KEY;
  if (!privateKey)
    throw new Error(
      "set AUTH_ETHEREUM_PRIVATE_KEY in the environment; do not pass or log a private key on the command line",
    );
  const input = JSON.parse(await readFile(contextPath, "utf8")) as Omit<
    SiweContext,
    "chainId"
  > & { chainId: string };
  await writeToml(
    outputPath,
    await createSiwe(privateKey, { ...input, chainId: BigInt(input.chainId) }),
  );
}
