/**
 * Host preparation for the native Noir Aadhaar Secure QR verifier
 * (noir/aadhaar_secure_qr).
 *
 * UIDAI signs the decompressed payload. The host turns the scanned decimal
 * string into bytes, decompresses them (gzip for UIDAI QRs, zlib for the
 * upstream Anon Aadhaar test QR), splits off the last 256 bytes as the RSA
 * signature and computes the delimiter hints. None of this is trusted: the
 * circuit checks the signature over the exact bytes and checks every hint.
 */
import {
  createPublicKey,
  verify as verifySignature,
  type KeyObject,
} from "node:crypto";
import { gunzipSync, inflateSync } from "node:zlib";
import { rsaKeyToCircuit } from "./oidc.js";
import { boundedBytes } from "./toml.js";

export const AADHAAR_SECURE_QR_SIGNATURE_BYTES = 256;
export const AADHAAR_SECURE_QR_DELIMITERS = 18;
/** Upstream AadhaarQRVerifier(121, 17, 1536) accepts at most 1527 signed bytes. */
export const AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES = 1527;

/** Decimal QR text to its minimal big-endian byte string. */
export function secureQrNumberToBytes(decimal: string): Buffer {
  const text = decimal.trim();
  if (!/^[1-9][0-9]*$/.test(text))
    throw new Error(
      "Secure QR text must be a positive decimal integer without leading zeros",
    );
  let hex = BigInt(text).toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.from(hex, "hex");
}

/**
 * Largest decompressed payload the host accepts (64 KiB). A QR code holds at
 * most 2,953 bytes, and the circuit accepts at most 1,527 signed bytes plus the
 * 256-byte signature, so real Secure QRs stay far below this limit. The limit
 * stops a crafted stream (a decompression bomb) from exhausting host memory.
 */
export const AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES = 64 * 1024;

function boundedDecompress(
  decompress: (bytes: Buffer, options: { maxOutputLength: number }) => Buffer,
  bytes: Buffer,
): Buffer {
  try {
    return decompress(bytes, {
      maxOutputLength: AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES,
    });
  } catch (error) {
    if ((error as { code?: string }).code === "ERR_BUFFER_TOO_LARGE")
      throw new Error(
        `Secure QR payload decompresses to more than ${AADHAAR_SECURE_QR_MAX_DECOMPRESSED_BYTES} bytes`,
      );
    throw error;
  }
}

/** Decompress a gzip (UIDAI) or zlib (upstream test QR) stream. */
export function decompressSecureQr(compressed: Uint8Array): Buffer {
  const bytes = Buffer.from(compressed);
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b)
    return boundedDecompress(gunzipSync, bytes);
  if (
    bytes.length >= 2 &&
    (bytes[0]! & 0x0f) === 8 &&
    ((bytes[0]! << 8) | bytes[1]!) % 31 === 0
  )
    return boundedDecompress(inflateSync, bytes);
  throw new Error("Secure QR bytes are neither a gzip nor a zlib stream");
}

export interface SplitSecureQr {
  signed: Buffer;
  signature: Buffer;
}

/** The last 256 decompressed bytes are the RSA-2048 signature over the rest. */
export function splitSecureQr(decompressed: Uint8Array): SplitSecureQr {
  const bytes = Buffer.from(decompressed);
  if (bytes.length <= AADHAAR_SECURE_QR_SIGNATURE_BYTES)
    throw new Error("Secure QR payload is too short");
  return {
    signed: bytes.subarray(0, bytes.length - AADHAAR_SECURE_QR_SIGNATURE_BYTES),
    signature: bytes.subarray(bytes.length - AADHAAR_SECURE_QR_SIGNATURE_BYTES),
  };
}

/** Indices of the first 18 bytes equal to 255 (the photo may contain more). */
export function secureQrDelimiterHints(signed: Uint8Array): number[] {
  const hints: number[] = [];
  for (
    let i = 0;
    i < signed.length && hints.length < AADHAAR_SECURE_QR_DELIMITERS;
    i++
  ) {
    if (signed[i] === 255) hints.push(i);
  }
  if (hints.length !== AADHAAR_SECURE_QR_DELIMITERS)
    throw new Error(
      `Secure QR has ${hints.length} delimiters before the photo; expected 18`,
    );
  return hints;
}

/** Little-endian 120-bit limbs of a big-endian integer, as rsa_signature expects. */
export function rsaLimbs(bytes: Uint8Array, count = 18): string[] {
  let value = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  const limbs: string[] = [];
  for (let i = 0; i < count; i++) {
    limbs.push((value & ((1n << 120n) - 1n)).toString());
    value >>= 120n;
  }
  if (value !== 0n)
    throw new Error("integer does not fit the RSA limb envelope");
  return limbs;
}

export interface SecureQrPreparation {
  input: {
    signed_data: { len: number; storage: number[] };
    signature: string[];
    modulus: string[];
    redc: string[];
    delimiters: number[];
  };
  signed: Buffer;
  signature: Buffer;
  hostSignatureValid: boolean;
}

/**
 * Build the Noir `SecureQrInput` for one issuer key. `capacity` is the
 * circuit's N. The host signature check is a convenience report only; the
 * circuit's check is the relation that counts.
 */
export function prepareSecureQrInput(
  payload: { qrDecimal: string } | { decompressed: Uint8Array },
  issuerPublicKey: KeyObject | string | Buffer,
  capacity = AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES,
): SecureQrPreparation {
  const decompressed =
    "qrDecimal" in payload
      ? decompressSecureQr(secureQrNumberToBytes(payload.qrDecimal))
      : Buffer.from(payload.decompressed);
  const { signed, signature } = splitSecureQr(decompressed);
  if (signed.length > capacity)
    throw new Error(
      `Secure QR signed data has ${signed.length} bytes; circuit capacity is ${capacity}`,
    );
  const key =
    typeof issuerPublicKey === "object" &&
    "asymmetricKeyType" in issuerPublicKey
      ? issuerPublicKey
      : createPublicKey(issuerPublicKey);
  if (key.asymmetricKeyType !== "rsa")
    throw new Error("Secure QR issuer key must be RSA");
  const circuitKey = rsaKeyToCircuit(key.export({ format: "jwk" }), 2048);
  const hostSignatureValid = verifySignature("sha256", signed, key, signature);
  return {
    input: {
      signed_data: boundedBytes(signed, capacity),
      signature: rsaLimbs(signature),
      modulus: circuitKey.modulus_limbs,
      redc: circuitKey.redc_params_limbs,
      delimiters: secureQrDelimiterHints(signed),
    },
    signed,
    signature,
    hostSignatureValid,
  };
}
