/** Preserve an illustrative public sample as rejected evidence, never a positive. */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash, createPublicKey, verify } from "node:crypto";
const out = new URL("../../../fixtures/material/philsys/provider-test/", import.meta.url);
await mkdir(out, { recursive: true });
const key = Buffer.from(
  "vD3czlgHEpf2sxGcri6iTm4zeEEA+jfd9tTq9S8zxe8=",
  "base64",
);
const fields = {
  DateIssued: "31 May 2021",
  Issuer: "PSA",
  subject: {
    Suffix: "",
    lName: "Mingiz",
    fName: "Plasti",
    mName: "Empre",
    sex: "Female",
    BF: "[1,10]",
    DOB: "March 01, 1947",
    POB: "Bindoy (Payabon),Negros Oriental",
    PCN: "1234-6015-6789-5037",
  },
  alg: "EDDSA",
};
const candidates = [
  "bvx1vw9QWx9V/CUISd0hED9+aZR9FEBk3GCfdwb2BOpan1nvLcst0AYCyF1ArBcaV0XFAJ5CMhRzyHUCeai6iDw==",
  "bvx1vw9QWx9V/CUlSd0hED9+aZR9FEBk3GCfdwb2BOpan1nvLcst0AYCyF1ArBcaV0XFAJ5CMhRzyHUCea6iDw==",
];
const message = Buffer.from(JSON.stringify(fields, null, 2), "latin1");
const pk = createPublicKey({
  key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), key]),
  format: "der",
  type: "spki",
});
const result = {
  source: "https://www.bsp.gov.ph/Regulations/Issuances/2021/M-2021-057.pdf",
  pdfPage: 20,
  transcriptionWarning:
    "Illustrative QR JSON transcribed from raster source. Uppercase I/l and sample spelling may be ambiguous; exact candidate strings preserved. Failure does not prove a particular cause or historical key rotation.",
  fields,
  publicKeyBase64: key.toString("base64"),
  publicKeyRawSha256: createHash("sha256").update(key).digest("hex"),
  messageHex: message.toString("hex"),
  candidates: candidates.map((signatureBase64) => ({
    signatureBase64,
    decodedLength: Buffer.from(signatureBase64, "base64").length,
    signatureVerified: verify(
      null,
      message,
      pk,
      Buffer.from(signatureBase64, "base64"),
    ),
  })),
  result: "signature-rejected",
  positiveIssuerVector: false,
};
if (result.candidates.some((c) => c.signatureVerified))
  throw Error("Evidence expectation changed; review before accepting");
await writeFile(
  new URL("sample-transcription-verification.json", out),
  JSON.stringify(result, null, 2) + "\n",
);
console.log(
  "Published illustrative sample: both preserved transcription candidates rejected by current official Ed25519 key. No positive issuer vector claimed.",
);
