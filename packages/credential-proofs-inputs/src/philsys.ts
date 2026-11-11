/** Legacy PSA JSON QR only; current COSE/digital formats are separate. */
import { createHash } from "node:crypto";
import { assertBoundedJsonObject } from "./oidc-json.js";
import { importVerifiedEd25519 } from "./ed25519.js";
export const PHILSYS_LEGACY_PUBLIC_KEY =
  "vD3czlgHEpf2sxGcri6iTm4zeEEA+jfd9tTq9S8zxe8=";
const subjectKeys = [
  "Suffix",
  "lName",
  "fName",
  "mName",
  "sex",
  "BF",
  "DOB",
  "POB",
  "PCN",
] as const;
function exactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  if (
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((k) => !keys.includes(k))
  )
    throw Error("Unexpected PhilSys fields");
}
function field(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > 64 ||
    [...value].some(
      (c) => c.charCodeAt(0) > 255 || /["\\\x00-\x1f\x7f]/.test(c),
    )
  )
    throw Error("Unsupported PhilSys Latin1 field");
  return value;
}
/** Explicit configured trust key; never read an issuer key from credential input. */
export function importVerifiedPhilSys(
  raw: string,
  trustedIssuerKey: Uint8Array,
) {
  const object = assertBoundedJsonObject(raw);
  exactKeys(object, ["DateIssued", "Issuer", "subject", "alg", "signature"]);
  if (object.Issuer !== "PSA" || object.alg !== "EDDSA")
    throw Error("Unsupported PhilSys issuer/algorithm");
  if (
    object.subject === null ||
    typeof object.subject !== "object" ||
    Array.isArray(object.subject)
  )
    throw Error("Invalid PhilSys subject");
  const subject = object.subject as Record<string, unknown>;
  exactKeys(subject, subjectKeys);
  const orderedSubject = Object.fromEntries(
    subjectKeys.map((k) => [k, field(subject[k])]),
  );
  const date = field(object.DateIssued);
  const signed = {
    DateIssued: date,
    Issuer: "PSA",
    subject: orderedSubject,
    alg: "EDDSA",
  };
  const message = Buffer.from(
    JSON.stringify(signed, null, 2).replace(/\u00f1|\u00d1/g, "?"),
    "latin1",
  );
  if (
    typeof object.signature !== "string" ||
    !/^[A-Za-z0-9+/]{86}==$/.test(object.signature)
  )
    throw Error("Invalid PhilSys base64 signature");
  const signature = Buffer.from(object.signature, "base64");
  if (signature.toString("base64") !== object.signature)
    throw Error("Noncanonical PhilSys base64 signature");
  const verified = importVerifiedEd25519(message, signature, trustedIssuerKey);
  // The circuit fields hold the signed spelling: the issuer signs U+00F1 and U+00D1 as
  // `?`, and philsys_auth rejects bytes 241 and 209 (one encoding per QR).
  const bytes = (value: string) => [
    ...Buffer.from(value.replace(/\u00f1|\u00d1/g, "?"), "latin1"),
  ];
  return {
    auth: {
      date_issued: bytes(date),
      suffix: bytes(orderedSubject.Suffix!),
      last_name: bytes(orderedSubject.lName!),
      first_name: bytes(orderedSubject.fName!),
      middle_name: bytes(orderedSubject.mName!),
      sex: bytes(orderedSubject.sex!),
      blood_finger: bytes(orderedSubject.BF!),
      date_of_birth: bytes(orderedSubject.DOB!),
      place_of_birth: bytes(orderedSubject.POB!),
      pcn: bytes(orderedSubject.PCN!),
      signature: verified.signature,
      issuer_hint: verified.public_hint,
      signature_hint: verified.signature_hint,
    },
    policy: {
      issuer_key: [...trustedIssuerKey],
      credential_digest: [...createHash("sha256").update(message).digest()],
    },
    signedMessage: message,
  };
}
