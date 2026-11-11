// Writes src/fixture.nr and fixtures/manifest.json for the native Aadhaar
// Secure QR attribute-gating instance. The QRs are the Anon Aadhaar public
// test QR (signed with the upstream test key, whose private key is
// published) and re-issues of its fields with chosen issuance times and
// dates of birth, signed with the public synthetic RS256 test key in
// fixtures/data. None is a UIDAI credential.
//
// node scripts/fixtures/generators/aadhaar_secure_qr.mjs \
//   --instance attribute-gating/aadhaar_secure_qr [--now <unix s>] [--max-age <s>]
//
// `--now` is the issuance time of the adult QR (UTC Unix seconds); the TXE
// tests mine their anchor blocks relative to it. Needs `npm ci && npm run
// build` in packages/credential-proofs-inputs. No network access, no proving.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const credentials = "packages/credential-proofs-inputs";
const {
  prepareSecureQrInput,
  decompressSecureQr,
  secureQrNumberToBytes,
  splitSecureQr,
  AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES: N,
} = await import("credential-proofs-inputs/aadhaar-secure-qr");
const generator =
  "aztec/use-cases/scripts/fixtures/generators/aadhaar_secure_qr.mjs";
const keyPath = `fixtures/data/synthetic-rs256-private.pem`;
const publicPath = `fixtures/data/synthetic-rs256-public.pem`;
const qrPath = `fixtures/material/anon_aadhaar/provider-test/test.json`;
const certificatePath = `fixtures/material/anon_aadhaar/provider-test/testCertificate.pem`;

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const IST = 19800;

// IST wall clock of a UTC Unix time, as the QR reference id writes it
// (YYYYMMDDhhmmssSSS, milliseconds 000).
function istStamp(unix) {
  const d = new Date((unix + IST) * 1000);
  const p = (v, n = 2) => String(v).padStart(n, "0");
  return `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}000`;
}
// Independent check: the reference-id stamp back to Unix seconds.
const stampUnix = (s) =>
  Date.UTC(
    +s.slice(0, 4),
    +s.slice(4, 6) - 1,
    +s.slice(6, 8),
    +s.slice(8, 10),
    +s.slice(10, 12),
    +s.slice(12, 14),
  ) /
    1000 -
  IST;

function fieldsOf(signed) {
  const parts = [];
  let start = 0;
  for (let i = 0; i < signed.length && parts.length < 18; i++)
    if (signed[i] === 255) {
      parts.push(Buffer.from(signed.subarray(start, i)));
      start = i + 1;
    }
  return { parts, photo: Buffer.from(signed.subarray(start)) };
}
const FF = Buffer.from([255]);
const build = (parts, photo) =>
  Buffer.concat([...parts.flatMap((p) => [p, FF]), photo]);
function filler(label, length) {
  const out = [];
  for (let i = 0; out.length < length; i++)
    out.push(...createHash("sha256").update(`${label}:${i}`).digest());
  return Buffer.from(out.slice(0, length));
}

const arr = (a) => `[${a.join(", ")}]`;
const qrExpression = (p) =>
  `AadhaarSecureQr {
        signed_data: BoundedVec::from_parts(${arr(p.input.signed_data.storage)}, ${p.input.signed_data.len}),
        signature: ${arr(p.input.signature)},
        modulus: ${arr(p.input.modulus)},
        redc: ${arr(p.input.redc)},
        delimiters: ${arr(p.input.delimiters)},
        max_age: QR_MAX_AGE,
    }`;

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      now: { type: "string", default: "4000000000" },
      "max-age": { type: "string", default: "10800" },
    },
  });
  if (values.instance !== "attribute-gating/aadhaar_secure_qr")
    throw new Error("--instance attribute-gating/aadhaar_secure_qr");
  const now = Number(values.now);
  const maxAge = Number(values["max-age"]);
  if (!Number.isSafeInteger(now) || now % 1 !== 0) throw new Error("--now");

  const testQr = JSON.parse(await readFile(repository + qrPath, "utf8"));
  const certificate = await readFile(repository + certificatePath, "utf8");
  const syntheticKey = createPrivateKey(
    await readFile(repository + keyPath, "utf8"),
  );
  const syntheticPublic = createPublicKey(syntheticKey);

  const upstream = prepareSecureQrInput(
    { qrDecimal: testQr.testQRData },
    certificate,
    N,
  );
  if (!upstream.hostSignatureValid)
    throw new Error("upstream test QR does not verify");
  const base = fieldsOf(
    splitSecureQr(decompressSecureQr(secureQrNumberToBytes(testQr.testQRData)))
      .signed,
  );
  const last4 = base.parts[2].toString("latin1").slice(0, 4);
  const birthYear = (unix, age) =>
    new Date((unix + IST) * 1000).getUTCFullYear() - age;

  // name -> [issued at, date of birth, photo label, note]
  const plan = {
    adult: [
      now,
      base.parts[4].toString("latin1"),
      null,
      "the upstream test fields re-issued at --now (holder born 01-01-1984)",
    ],
    reissue: [
      now + 120,
      base.parts[4].toString("latin1"),
      "reissue-photo",
      "the same person re-issued 120 s later with another photo",
    ],
    minor: [
      now,
      `01-01-${birthYear(now, 10)}`,
      "minor-photo",
      "a 10-year-old holder, issued at --now",
    ],
    turns_18: [
      now,
      (() => {
        const d = new Date((now + IST) * 1000);
        const p = (v) => String(v).padStart(2, "0");
        return `${p(d.getUTCDate())}-${p(d.getUTCMonth() + 1)}-${d.getUTCFullYear() - 18}`;
      })(),
      "turns-18-photo",
      "a holder whose 18th birthday is the IST issuance date (inclusive)",
    ],
  };
  const prepared = { upstream };
  const claims = {
    upstream: {
      note: "Anon Aadhaar public test QR, upstream test key (private key published upstream)",
      issued_at: stampUnix(base.parts[2].toString("latin1").slice(4)),
      date_of_birth: base.parts[4].toString("latin1"),
      signed_sha256: sha256(upstream.signed),
    },
  };
  for (const [name, [issued, dob, photoLabel, note]] of Object.entries(plan)) {
    const parts = base.parts.map((p) => Buffer.from(p));
    const stamp = istStamp(issued);
    if (stampUnix(stamp) !== issued) throw new Error(`time round trip ${name}`);
    parts[2] = Buffer.from(`${last4}${stamp}`, "latin1");
    parts[4] = Buffer.from(dob, "latin1");
    const photo = photoLabel
      ? Buffer.concat([
          base.photo.subarray(0, 4),
          filler(photoLabel, base.photo.length - 4),
        ])
      : base.photo;
    const signed = build(parts, photo);
    const p = prepareSecureQrInput(
      {
        decompressed: Buffer.concat([
          signed,
          sign("sha256", signed, syntheticKey),
        ]),
      },
      syntheticPublic,
      N,
    );
    if (!p.hostSignatureValid)
      throw new Error(`host signature check failed for ${name}`);
    prepared[name] = p;
    claims[name] = {
      note,
      issued_at: issued,
      reference_id: `${last4}${stamp}`,
      date_of_birth: dob,
      signed_sha256: sha256(signed),
    };
  }

  const unformatted = `//! Generated by scripts/fixtures/generators/aadhaar_secure_qr.mjs; see fixtures/manifest.json. Do not edit.
//! \`upstream\` is the Anon Aadhaar public test QR (its signing key is published
//! upstream). The others carry its fields re-issued at chosen times and dates
//! of birth, signed with the public synthetic RS256 test key in
//! fixtures/data. None is a UIDAI credential.
use uc_adapter_aadhaar_secure_qr::AadhaarSecureQr;

/// The issuance time of \`adult\`, \`minor\` and \`turns_18\` (UTC Unix seconds).
pub global NOW: u64 = ${now};
/// The maximum QR age that every fixture input pins.
pub global QR_MAX_AGE: u64 = ${maxAge};
/// The issuance time of \`reissue\`.
pub global REISSUE_ISSUED_AT: u64 = ${now + 120};
/// The issuance time of \`upstream\` (2024-04-20 01:45:52 IST).
pub global UPSTREAM_ISSUED_AT: u64 = ${claims.upstream.issued_at};

${["adult", "reissue", "minor", "turns_18", "upstream"]
  .map(
    (name) =>
      `/// ${claims[name].note[0].toUpperCase()}${claims[name].note.slice(1)}.\npub fn ${name}() -> AadhaarSecureQr {\n    ${qrExpression(prepared[name])}\n}`,
  )
  .join("\n\n")}
`;
  const fixture = formatNoir(unformatted);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const inputs = {};
  for (const path of [
    keyPath,
    publicPath,
    qrPath,
    certificatePath,
    `${credentials}/src/aadhaar-secure-qr.ts`,
    generator,
  ])
    inputs[path] = sha256(await readFile(repository + path));
  const record = {
    schema: "uc-fixture-v1",
    scheme: "aadhaar_secure_qr",
    use_case: "attribute-gating",
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/aadhaar_secure_qr.mjs",
        "--instance",
        values.instance,
        "--now",
        String(now),
        "--max-age",
        String(maxAge),
      ],
      cwd: "aztec/use-cases",
      library:
        "packages/credential-proofs-inputs prepareSecureQrInput; node:crypto RSA-SHA256 (PKCS#1 v1.5)",
    },
    inputs,
    key_provenance:
      "Public synthetic RS256 test key committed in fixtures/data, and the Anon Aadhaar upstream test key (testCertificate.pem; its private key is published upstream). Neither is a UIDAI key. Anyone can sign with either.",
    claims: { now, qr_max_age: maxAge, qrs: claims },
    notes: [
      "Re-issued QRs keep the upstream test fields (name, gender, address, last four digits 2697) and change only the reference-id time, the date of birth and the photo bytes.",
      "Negative cases mutate a valid QR in src/test.nr (signature, signed byte, modulus, maximum age).",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(
    JSON.stringify(
      Object.fromEntries(
        Object.entries(claims).map(([k, v]) => [
          k,
          [v.issued_at, v.date_of_birth],
        ]),
      ),
    ),
  );
}

await main();
