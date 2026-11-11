import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { p256 } from "@noble/curves/p256";
import {
  bytesFromHex,
  paddedBytes,
  writeToml,
  type TomlDocument,
} from "./toml.js";

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const P256_ORDER =
  0xffff_ffff_0000_0000_ffff_ffff_ffff_ffff_bce6_faad_a717_9e84_f3b9_cac2_fc63_2551n;
// Capacities of the Noir verifier inputs (WebAuthnAssertion<256>, WebAuthnPolicy<64, 128>).
const CLIENT_MAX = 256;
const RP_MAX = 64;
const ORIGIN_MAX = 128;
// The member that Chromium appends to about one ceremony in five; pinned byte for byte.
const CHROMIUM_EXTRA_MEMBER =
  ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';

export type PasskeyChallenge = {
  challenge: string;
  challenge_base64url: string;
  rp_id: string;
  origin: string;
};

export function makePasskeyChallenge(
  rpId: string,
  origin: string,
): PasskeyChallenge {
  const url = new URL(origin);
  if (url.protocol !== "https:" && url.hostname !== "localhost")
    throw new Error(
      "WebAuthn capture origin must use HTTPS (localhost is allowed for development)",
    );
  if (url.origin !== origin)
    throw new Error("origin must be a canonical origin without a path");
  if (
    !/^[a-z0-9.-]+$/.test(rpId) ||
    !(url.hostname === rpId || url.hostname.endsWith(`.${rpId}`))
  ) {
    throw new Error(
      "RP ID must be an ASCII domain equal to or a parent of the origin host",
    );
  }
  const bytes = Buffer.concat([Buffer.from([0]), randomBytes(31)]);
  const challenge = BigInt(`0x${bytes.toString("hex")}`);
  if (challenge >= FIELD_MODULUS)
    throw new Error("generated challenge is outside the Noir Field range");
  return {
    challenge: challenge.toString(),
    challenge_base64url: bytes.toString("base64url"),
    rp_id: rpId,
    origin,
  };
}

function decodeBase64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(value))
    throw new Error("expected base64url data from the browser capture page");
  return Buffer.from(value, "base64url");
}

function derEcdsaToRaw(der: Buffer): Buffer {
  let offset = 0;
  if (der[offset++] !== 0x30)
    throw new Error("WebAuthn signature is not DER encoded ECDSA");
  let sequenceLength = der[offset++]!;
  if ((sequenceLength & 0x80) !== 0) {
    const count = sequenceLength & 0x7f;
    if (count < 1 || count > 2 || offset + count > der.length)
      throw new Error("invalid DER signature length");
    sequenceLength = 0;
    for (let i = 0; i < count; i++)
      sequenceLength = (sequenceLength << 8) | der[offset++]!;
  }
  const end = offset + sequenceLength;
  const integer = (): Buffer => {
    if (der[offset++] !== 0x02) throw new Error("invalid DER ECDSA integer");
    const length = der[offset++]!;
    const bytes = der.subarray(offset, offset + length);
    offset += length;
    let first = 0;
    while (first < bytes.length - 1 && bytes[first] === 0) first++;
    const magnitude = bytes.subarray(first);
    if (magnitude.length > 32) throw new Error("ECDSA scalar exceeds 32 bytes");
    return Buffer.concat([Buffer.alloc(32 - magnitude.length), magnitude]);
  };
  const r = integer();
  const s = integer();
  if (offset !== end || end !== der.length)
    throw new Error("malformed DER ECDSA signature");
  const scalar = (bytes: Buffer) => BigInt(`0x${bytes.toString("hex")}`);
  const rScalar = scalar(r);
  const sScalar = scalar(s);
  if (
    rScalar === 0n ||
    rScalar >= P256_ORDER ||
    sScalar === 0n ||
    sScalar >= P256_ORDER
  ) {
    throw new Error("ECDSA signature scalar is outside the P-256 group order");
  }
  // Noir's stdlib verifier requires low-s signatures. Replacing s by n-s
  // preserves the valid ECDSA assertion while choosing its canonical form.
  const canonicalS = sScalar > P256_ORDER / 2n ? P256_ORDER - sScalar : sScalar;
  const canonicalBytes = Buffer.from(
    canonicalS.toString(16).padStart(64, "0"),
    "hex",
  );
  return Buffer.concat([r, canonicalBytes]);
}

/**
 * Mirror of the Noir clientDataJSON check (passkey `assert_valid_webauthn`).
 * The fixed prefix `{"type":"webauthn.get","challenge":"...","origin":"..."` must
 * be followed by exactly `}` (Safari and iOS), `,"crossOrigin":false}`
 * (Chrome, Edge, Android Chrome, Firefox), or `,"crossOrigin":false` plus
 * Chromium's fixed extra member and `}`. Every other byte sequence is rejected.
 */
export function checkClientDataProfile(
  clientData: Buffer,
  expectedChallenge: string,
  origin: string,
): void {
  const originBytes = Buffer.from(origin);
  if (originBytes.length === 0 || originBytes.length > ORIGIN_MAX)
    throw new Error(`origin must be 1 to ${ORIGIN_MAX} bytes`);
  if (originBytes.some((byte) => byte < 0x20 || byte === 0x22 || byte === 0x5c))
    throw new Error("origin contains a control byte, quote or backslash");
  if (91 + originBytes.length + 22 > CLIENT_MAX)
    throw new Error(
      "origin is too long for the verifier's clientDataJSON capacity",
    );
  if (clientData.length > CLIENT_MAX) {
    throw new Error(
      `clientDataJSON is ${clientData.length} bytes, above the verifier capacity of ${CLIENT_MAX}; repeat the ceremony (Chromium adds an optional member to some assertions)`,
    );
  }
  const prefix = `{"type":"webauthn.get","challenge":"${expectedChallenge}","origin":"${origin}"`;
  if (
    !clientData
      .subarray(0, Buffer.byteLength(prefix))
      .equals(Buffer.from(prefix))
  ) {
    throw new Error(
      "clientDataJSON type, challenge or origin does not match the expected values",
    );
  }
  const rest = clientData
    .subarray(Buffer.byteLength(prefix))
    .toString("latin1");
  const crossOriginFalse = ',"crossOrigin":false';
  if (rest !== "}" && !rest.startsWith(crossOriginFalse))
    throw new Error("clientDataJSON crossOrigin must be false or omitted");
  if (
    rest !== "}" &&
    rest !== `${crossOriginFalse}}` &&
    rest !== `${crossOriginFalse}${CHROMIUM_EXTRA_MEMBER}}`
  ) {
    throw new Error("clientDataJSON has an unsupported length or extra member");
  }
  let parsed: {
    type?: unknown;
    challenge?: unknown;
    origin?: unknown;
    crossOrigin?: unknown;
    topOrigin?: unknown;
  };
  try {
    parsed = JSON.parse(clientData.toString("utf8")) as typeof parsed;
  } catch {
    throw new Error("clientDataJSON is not valid JSON");
  }
  if (
    parsed.type !== "webauthn.get" ||
    parsed.challenge !== expectedChallenge ||
    parsed.origin !== origin ||
    (parsed.crossOrigin !== undefined && parsed.crossOrigin !== false) ||
    parsed.topOrigin !== undefined
  ) {
    throw new Error("clientDataJSON members do not match the expected values");
  }
}

export function passkeyAssertionToCircuit(
  assertion: unknown,
  policy: {
    challenge: string;
    rpId: string;
    origin: string;
    publicKeySec1: string;
    requireUserVerification: boolean;
  },
): TomlDocument {
  const response = assertion as {
    response?: {
      authenticatorData?: string;
      clientDataJSON?: string;
      signature?: string;
    };
  };
  if (
    !response?.response?.authenticatorData ||
    !response.response.clientDataJSON ||
    !response.response.signature
  ) {
    throw new Error(
      "capture JSON must include authenticatorData, clientDataJSON, and signature",
    );
  }
  const challenge = BigInt(policy.challenge);
  if (challenge < 0n || challenge >= FIELD_MODULUS)
    throw new Error("challenge is outside the Noir Field range");
  const challengeBytes = Buffer.from(
    challenge.toString(16).padStart(64, "0"),
    "hex",
  );
  const expectedChallenge = challengeBytes.toString("base64url");
  if (!policy.rpId || policy.origin !== new URL(policy.origin).origin)
    throw new Error("RP ID or canonical origin is invalid");
  const clientData = decodeBase64url(response.response.clientDataJSON);
  checkClientDataProfile(clientData, expectedChallenge, policy.origin);
  if (Buffer.byteLength(policy.rpId) > RP_MAX)
    throw new Error(`RP ID exceeds the verifier capacity of ${RP_MAX} bytes`);
  const authenticatorData = decodeBase64url(
    response.response.authenticatorData,
  );
  if (authenticatorData.length !== 37)
    throw new Error(
      "verifier accepts exactly 37-byte authenticatorData without extensions",
    );
  const rpHash = createHash("sha256").update(policy.rpId).digest();
  if (!rpHash.equals(authenticatorData.subarray(0, 32)))
    throw new Error(
      "authenticatorData RP ID hash does not match expected RP ID",
    );
  const flags = authenticatorData[32]!;
  if ((flags & 1) !== 1)
    throw new Error("authenticator did not set user-present flag");
  if (policy.requireUserVerification && (flags & 4) !== 4)
    throw new Error("authenticator did not set user-verified flag");
  if ((flags & 0x22) !== 0)
    throw new Error("authenticatorData sets a reserved flag bit");
  if ((flags & 0xc0) !== 0)
    throw new Error(
      "authenticatorData carries attested credential data or extensions",
    );
  if ((flags & 0x10) !== 0 && (flags & 0x08) === 0)
    throw new Error(
      "authenticatorData sets backup state without backup eligibility",
    );

  const publicKey = bytesFromHex(policy.publicKeySec1, 65);
  if (publicKey[0] !== 4)
    throw new Error(
      "expected uncompressed SEC1 P-256 public key (04 || x || y)",
    );
  try {
    p256.ProjectivePoint.fromHex(publicKey).assertValidity();
  } catch {
    throw new Error("public key is not a valid P-256 point");
  }
  const derSignature = decodeBase64url(response.response.signature);
  const signature = derEcdsaToRaw(derSignature);
  const messageHash = createHash("sha256")
    .update(
      Buffer.concat([
        authenticatorData,
        createHash("sha256").update(clientData).digest(),
      ]),
    )
    .digest();
  if (!p256.verify(signature, messageHash, publicKey, { lowS: true }))
    throw new Error(
      "passkey signature does not verify under the registered key",
    );
  return {
    challenge: challenge.toString(),
    assertion: {
      authenticator_data: paddedBytes(authenticatorData, 37),
      client_data_json: paddedBytes(clientData, CLIENT_MAX),
      client_data_json_len: clientData.length,
      signature: Array.from(signature),
    },
    policy: {
      origin: paddedBytes(Buffer.from(policy.origin), ORIGIN_MAX),
      origin_len: Buffer.byteLength(policy.origin),
      require_user_verification: policy.requireUserVerification,
      rp_id: paddedBytes(Buffer.from(policy.rpId), RP_MAX),
      rp_id_len: Buffer.byteLength(policy.rpId),
    },
    public_key: {
      x: Array.from(publicKey.subarray(1, 33)),
      y: Array.from(publicKey.subarray(33, 65)),
    },
  };
}

export async function writeChallenge(
  path: string,
  rpId: string,
  origin: string,
): Promise<void> {
  await writeFile(
    path,
    `${JSON.stringify(makePasskeyChallenge(rpId, origin), null, 2)}\n`,
    { mode: 0o600 },
  );
}

export async function importPasskeyAssertion(
  inputPath: string,
  outputPath: string,
  policy: Parameters<typeof passkeyAssertionToCircuit>[1],
): Promise<void> {
  const data = JSON.parse(await readFile(inputPath, "utf8")) as unknown;
  await writeToml(outputPath, passkeyAssertionToCircuit(data, policy));
}
