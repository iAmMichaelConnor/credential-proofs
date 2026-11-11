// Writes src/fixture.nr and fixtures/manifest.json for the PhilSys
// attribute-gating instance, and the adapter's src/fixture.nr (the instance QR
// for the adapter's constrained test, which runs without TXE): legacy PhilID JSON QRs signed with public
// synthetic Ed25519 issuer keys (seed bytes 42 and 43, the same local test
// convention as scripts/fixtures/generate-philsys-local.mjs).
// None is PSA-issued; none is a real PhilID.
//
// node scripts/fixtures/generators/philsys.mjs [--instance attribute-gating/philsys]
//
// Each QR is signed here and then imported with the library's
// importVerifiedPhilSys (strict Ed25519 host verification, point hints and
// the SHA-256 of the official serialization). Needs `npm ci && npm run build`
// in packages/credential-proofs-inputs. No network access, no proving.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const credentials = "packages/credential-proofs-inputs";
const generator = "aztec/use-cases/scripts/fixtures/generators/philsys.mjs";
const { importVerifiedPhilSys } = await import(
  `credential-proofs-inputs/philsys`
);

const { ed25519 } = await import("@noble/curves/ed25519");

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Ed25519 group order and little-endian scalar helpers (RFC 8032).
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (bytes) =>
  BigInt(`0x${Buffer.from(bytes).reverse().toString("hex")}`);
const scalarBytes = (n) =>
  Buffer.from(n.toString(16).padStart(64, "0"), "hex").reverse();

// A second valid RFC 8032 signature over `message`: the same equation
// s = r + H(R || A || M) * a (mod L), with another nonce r. Another valid
// witness of the same credential, for the second-use test.
function resign(key, message, label) {
  const h = createHash("sha512").update(Buffer.alloc(32, key.seed)).digest();
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;
  const a = le(h.subarray(0, 32));
  const r = le(createHash("sha512").update(label).digest()) % L;
  const R = Buffer.from(ed25519.ExtendedPoint.BASE.multiply(r).toRawBytes());
  const k =
    le(
      createHash("sha512")
        .update(Buffer.concat([R, key.publicKey, message]))
        .digest(),
    ) % L;
  return Buffer.concat([R, scalarBytes((r + k * a) % L)]).toString("base64");
}

// A public synthetic issuer: the Ed25519 key whose 32-byte seed is `seed`
// repeated. Anyone can sign with it.
function issuer(seed) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, seed),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = Buffer.from(
    createPublicKey(privateKey).export({ format: "jwk" }).x,
    "base64url",
  );
  return { seed, privateKey, publicKey };
}

// Signs the official serialization exactly as importVerifiedPhilSys rebuilds
// it (field order, two-space indent, ñ/Ñ as ?), then imports and verifies.
function signedQr(key, fields) {
  const signed = {
    DateIssued: fields.DateIssued,
    Issuer: "PSA",
    subject: fields.subject,
    alg: "EDDSA",
  };
  const message = Buffer.from(
    JSON.stringify(signed, null, 2).replace(/ñ|Ñ/g, "?"),
    "latin1",
  );
  const qr = {
    ...signed,
    signature: sign(null, message, key.privateKey).toString("base64"),
  };
  const imported = importVerifiedPhilSys(JSON.stringify(qr), key.publicKey);
  return { qr, imported, message };
}

const subject = (overrides) => ({
  Suffix: "",
  lName: "TEST",
  fName: "SYNTHETIC",
  mName: "ONLY",
  sex: "Female",
  BF: "[1,10]",
  DOB: "March 01, 1947",
  POB: "Synthetic Town",
  PCN: "0000-0000-0000-0000",
  ...overrides,
});

const array = (values) => `[${[...values].map(String).join(", ")}]`;
const bounded = (values) => `BoundedVec::from_array(${array(values)})`;
const point = (h) =>
  `Point { x_limbs: ${array(h.x_limbs)}, y_limbs: ${array(h.y_limbs)} }`;

function qrFunction(name, doc, imported) {
  const a = imported.auth;
  const p = imported.policy;
  const fields = [
    "date_issued",
    "suffix",
    "last_name",
    "first_name",
    "middle_name",
    "sex",
    "blood_finger",
    "date_of_birth",
    "place_of_birth",
    "pcn",
  ]
    .map((k) => `        ${k}: ${bounded(a[k])},`)
    .join("\n");
  return `/// ${doc}
pub fn ${name}() -> PhilsysQr {
    PhilsysQr {
${fields}
        signature: ${array(a.signature)},
        issuer_hint: ${point(a.issuer_hint)},
        signature_hint: ${point(a.signature_hint)},
        issuer_key: ${array(p.issuer_key)},
        credential_digest: ${array(p.credential_digest)},
    }
}
`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string", default: "attribute-gating/philsys" },
    },
  });
  if (values.instance !== "attribute-gating/philsys")
    throw Error("Only attribute-gating/philsys is supported");
  const pinned = issuer(42);
  const other = issuer(43);
  const base = { DateIssued: "31 May 2021" };
  const qrs = {
    qr: {
      doc: "The instance's QR: the library's synthetic fields, signed by the pinned issuer.",
      ...signedQr(pinned, { ...base, subject: subject({}) }),
    },
    other_person: {
      doc: "Another person's QR from the same issuer (another credential).",
      ...signedQr(pinned, {
        DateIssued: "02 June 2022",
        subject: subject({
          lName: "SAMPLE",
          fName: "SECOND",
          mName: "",
          sex: "Male",
          DOB: "July 15, 1990",
          PCN: "0000-0000-0000-0001",
        }),
      }),
    },
    enye: {
      doc: "A QR whose last name has an enye, signed and given as `?` (the official serialization).",
      ...signedQr(pinned, {
        ...base,
        subject: subject({ lName: "PEÑA", PCN: "0000-0000-0000-0002" }),
      }),
    },
    other_issuer: {
      doc: "The instance's fields signed by another synthetic issuer key.",
      ...signedQr(other, { ...base, subject: subject({}) }),
    },
  };
  {
    const { qr, message } = qrs.enye;
    const signature = resign(
      pinned,
      message,
      "credential-proofs philsys second nonce",
    );
    if (signature === qr.signature)
      throw Error("the second signature must differ");
    const resigned = { ...qr, signature };
    qrs.enye_resigned = {
      doc: "`enye()` with a second valid signature (another nonce): the same credential.",
      qr: resigned,
      message,
      imported: importVerifiedPhilSys(
        JSON.stringify(resigned),
        pinned.publicKey,
      ),
    };
  }
  const header = `//! Generated by scripts/fixtures/generators/philsys.mjs; see fixtures/manifest.json. Do not edit.
//! Legacy PhilID QRs signed with public synthetic Ed25519 test keys (seed
//! bytes 42 and 43). Not PSA-issued; not a real PhilID.
use uc_adapter_philsys::{PhilsysQr, Point};

/// The pinned synthetic issuer key (seed bytes 42).
pub global ISSUER_KEY: [u8; 32] = ${array(pinned.publicKey)};
/// Another synthetic issuer key (seed bytes 43).
pub global OTHER_ISSUER_KEY: [u8; 32] = ${array(other.publicKey)};
`;
  const fixture = formatNoir(
    header +
      Object.entries(qrs)
        .map(([name, q]) => "\n" + qrFunction(name, q.doc, q.imported))
        .join(""),
  );
  // The adapter's constrained test (adapters/philsys/src/tests.nr) runs the
  // instance QR under the ACVM without a TXE session.
  const adapterFixture = formatNoir(
    `//! Generated by scripts/fixtures/generators/philsys.mjs; see
//! attribute-gating/philsys/fixtures/manifest.json. Do not edit.
//! The instance QR of attribute-gating/philsys for the constrained adapter
//! test, signed with a public synthetic Ed25519 test key (seed bytes 42). Not
//! PSA-issued; not a real PhilID.
use crate::{PhilsysQr, Point};

/// The pinned synthetic issuer key (seed bytes 42).
pub global ISSUER_KEY: [u8; 32] = ${array(pinned.publicKey)};

` + qrFunction("qr", qrs.qr.doc, qrs.qr.imported),
  );
  const adapterPath = "adapters/philsys/src/fixture.nr";
  await writeFile(`${project}${adapterPath}`, adapterFixture);
  const directory = `${project}${values.instance}/`;
  await mkdir(`${directory}src`, { recursive: true });
  await mkdir(`${directory}fixtures`, { recursive: true });
  await writeFile(`${directory}src/fixture.nr`, fixture);

  const manifestPath = `${directory}fixtures/manifest.json`;
  const inputs = {};
  for (const path of [
    generator,
    `${credentials}/src/philsys.ts`,
    `${credentials}/src/ed25519.ts`,
  ])
    inputs[path] = sha256(await readFile(repository + path));
  const record = {
    schema: "uc-fixture-v1",
    scheme: "philsys",
    use_case: "attribute-gating",
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/philsys.mjs",
        "--instance",
        values.instance,
      ],
      cwd: "aztec/use-cases",
      library:
        "node:crypto Ed25519; importVerifiedPhilSys (packages/credential-proofs-inputs)",
    },
    inputs,
    key_provenance:
      "Public synthetic Ed25519 issuer keys whose seeds are 32 bytes of 42 (pinned) and 43 (other). Not the PSA key; anyone can sign with them.",
    claims: Object.fromEntries(
      Object.entries(qrs).map(([name, q]) => [
        name,
        {
          issuer_seed_byte: name === "other_issuer" ? 43 : 42,
          qr: q.qr,
          signed_message_sha256: sha256(q.message),
        },
      ]),
    ),
    notes: [
      "Synthetic legacy PhilID JSON QRs in the profile that philsys_auth accepts; not PSA-issued and not real persons.",
      "Negative cases (tampered fields, wrong digest, the enye in its unsigned spelling) mutate these QRs in src/test.nr.",
    ],
    outputs: {
      "src/fixture.nr": sha256(Buffer.from(fixture)),
      [`../../${adapterPath}`]: sha256(Buffer.from(adapterFixture)),
    },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(
    `wrote ${values.instance}/src/fixture.nr, ${adapterPath} and fixtures/manifest.json`,
  );
}

await main();
