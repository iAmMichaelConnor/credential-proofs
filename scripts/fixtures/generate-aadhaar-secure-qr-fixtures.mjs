// Generate inputs for the native Noir Aadhaar Secure QR library and its known-answer test.
// Run `npm run build` first. Writes:
//   noir/aadhaar_secure_qr/src/vectors.nr  (unit-test vectors)
//   target/kat/aadhaar_secure_qr/Prover*.toml  (known-answer test inputs)
//   fixtures/material/aadhaar_secure_qr/local-test/synthetic-vectors.json
// The happy path is the upstream Anon Aadhaar public test QR (its signing key
// is published upstream; it is not a UIDAI credential). Boundary vectors are
// that QR's fields rearranged and re-signed with this package's public
// synthetic RSA-2048 test key. Expected values are computed here with
// independent host code (Date.UTC, string parsing), not read from Noir.
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { prepareSecureQrInput, decompressSecureQr, secureQrNumberToBytes, splitSecureQr, rsaLimbs, AADHAAR_SECURE_QR_UPSTREAM_MAX_SIGNED_BYTES as N } from "credential-proofs-inputs/aadhaar-secure-qr";

import { stringifyToml } from "credential-proofs-inputs/toml";


const auth = new URL("../../", import.meta.url);
const material = new URL(
  "fixtures/material/anon_aadhaar/provider-test/",
  auth,
);
const testQr = JSON.parse(
  await readFile(new URL("test.json", material), "utf8"),
);
const testCertificate = await readFile(
  new URL("testCertificate.pem", material),
  "utf8",
);
const syntheticKey = createPrivateKey(
  await readFile(
    new URL("fixtures/data/synthetic-rs256-private.pem", auth),
    "utf8",
  ),
);
const syntheticPublic = createPublicKey(syntheticKey);

// UIDAI offline-QR certificate valid 2021-02-26 to 2024-02-27 (expired). Modulus
// copied from anon-aadhaar@4dad918 packages/circuits/assets/
// uidai_offline_publickey_26022021.cer (sha256 288475ef...e4847f). Upstream
// productionPublicKeyHash for it is 18063425...3484; a Noir test checks it.
const UIDAI_2021_MODULUS =
  "a2722c0e5f2de5ba707ed93f036ec2b1f0b955932390facc0f0bcbf20c80a15c088b4886866b72eb25ab0bf55a2fe06b69edbd5cc83b74c7709db2141e6c07c68bcdf859d3daf7f3fced241d072055dc15488474b45c2c982fa954aa52aa6fffb2481861c65085d84b64158e9f43d9f35ca69b48ce9300522102a4cae093bffd474b08d32d1d0406f687f7e55bd226a2384bf58a41c384c3974f1c7c5115819c926de3adf3ecbb9904c486f1f5d5303977bea63584367329b5c168afdc95121731f7f48d43af7cf31f69b1e3bbe7949dc7a8b10c0bddebababdebea076a1cf8166adf06a8a41dedf143bff835dbd2bd5bb0b61d2472c234a6d4411bc9b536095";

// issuer_key_hash() of the synthetic key; the Noir test synthetic_issuer_key_hash_is_recorded checks it.
const SYNTHETIC_KEY_HASH =
  "0x261e7b55eb91de2d791f8b54d62c71acf46f8535a8a942236cbfbd7fa7da12d9";

// Independent host oracle: IST wall clock (YYYYMMDDhhmmss...) to Unix seconds.
const istUnix = (stamp) =>
  Date.UTC(
    +stamp.slice(0, 4),
    +stamp.slice(4, 6) - 1,
    +stamp.slice(6, 8),
    +stamp.slice(8, 10),
    +stamp.slice(10, 12),
    +stamp.slice(12, 14),
  ) /
    1000 -
  19800;

const upstreamDecompressed = decompressSecureQr(
  secureQrNumberToBytes(testQr.testQRData),
);
const upstream = splitSecureQr(upstreamDecompressed).signed;
const FF = Buffer.from([255]);
function fieldsOf(signed) {
  const parts = [];
  let start = 0;
  for (let i = 0; i < signed.length && parts.length < 18; i++)
    if (signed[i] === 255) {
      parts.push(signed.subarray(start, i));
      start = i + 1;
    }
  return {
    parts: parts.map((p) => Buffer.from(p)),
    photo: Buffer.from(signed.subarray(start)),
  };
}
function build(parts, photo) {
  return Buffer.concat([...parts.flatMap((p) => [p, FF]), photo]);
}
function stream(label, length) {
  // deterministic non-secret filler bytes
  const out = [];
  for (let i = 0; out.length < length; i++)
    out.push(...createHash("sha256").update(`${label}:${i}`).digest());
  return Buffer.from(out.slice(0, length));
}
const base = fieldsOf(upstream);
const withFields = (changes, photo = base.photo) => {
  const parts = base.parts.map((p) => Buffer.from(p));
  for (const [i, v] of Object.entries(changes))
    parts[+i] = Buffer.from(v, "latin1");
  return build(parts, photo);
};
const refid = (stamp) => `2697${stamp}`;

const synthetic = {
  s2032: {
    note: "Leap-day boundary: 2032-03-01 12:00:00.000 IST",
    signed: withFields({ 2: refid("20320301120000000") }),
  },
  reissue: {
    note: "same identity, later re-issue (2033-07-15 08:30:15.250 IST) with a different photo",
    signed: withFields(
      { 2: refid("20330715083015250") },
      Buffer.concat([
        base.photo.subarray(0, 4),
        stream("photo", base.photo.length - 4),
      ]),
    ),
  },
  renamed: {
    note: "same as s2032 with a different name",
    signed: withFields({
      2: refid("20320301120000000"),
      3: "Sumit Kumar Singh",
    }),
  },
  maximal: {
    note: "155-byte name, 64-byte state, leap-day birth, 1527 signed bytes",
    signed: null,
  },
  long_name: {
    note: "156-byte name: valid signature, unsupported length",
    signed: withFields({ 3: "N".repeat(156) }),
  },
};
{
  const parts = base.parts.map((p) => Buffer.from(p));
  parts[2] = Buffer.from(refid("20220228235959999"));
  parts[3] = Buffer.from("A".repeat(155));
  parts[4] = Buffer.from("29-02-2004");
  parts[5] = Buffer.from("F");
  parts[11] = Buffer.from("560001");
  parts[13] = Buffer.from("S".repeat(64));
  const prefix = build(parts, Buffer.alloc(0));
  synthetic.maximal.signed = Buffer.concat([
    prefix,
    base.photo.subarray(0, 4),
    stream("maximal-photo", N - prefix.length - 4),
  ]);
  if (synthetic.maximal.signed.length !== N)
    throw new Error("maximal vector length");
}

const upstreamPrepared = prepareSecureQrInput(
  { qrDecimal: testQr.testQRData },
  testCertificate,
);
if (!upstreamPrepared.hostSignatureValid)
  throw new Error(
    "upstream test QR signature does not verify with the test certificate",
  );
const prepared = { upstream: upstreamPrepared };
for (const [name, v] of Object.entries(synthetic)) {
  const decompressed = Buffer.concat([
    v.signed,
    sign("sha256", v.signed, syntheticKey),
  ]);
  prepared[name] = prepareSecureQrInput({ decompressed }, syntheticPublic);
  if (!prepared[name].hostSignatureValid)
    throw new Error(`host signature check failed for ${name}`);
}
const summary = (p) => {
  const { parts } = fieldsOf(p.signed);
  const text = (i) => parts[i].toString("latin1");
  return {
    issued_at: istUnix(text(2).slice(4)),
    last4: text(2).slice(0, 4),
    name: text(3),
    dob: text(4),
    gender: text(5),
    pincode: text(11),
    state: text(13),
    length: p.signed.length,
    delimiters: p.input.delimiters,
  };
};

// Noir vectors.
const arr = (a) => `[${a.join(", ")}]`;
const input = (p) =>
  `SecureQrInput { signed_data: BoundedVec::from_parts(${arr(p.input.signed_data.storage)}, ${p.input.signed_data.len}), signature: ${arr(p.input.signature)}, modulus: ${arr(p.input.modulus)}, redc: ${arr(p.input.redc)}, delimiters: ${arr(p.input.delimiters)} }`;
let nr =
  "//! Generated by scripts/fixtures/generate-aadhaar-secure-qr-fixtures.mjs.\n//! Do not edit. `upstream` is the Anon Aadhaar public test QR (published test key).\n//! The others are re-signed with the public synthetic test key\n//! fixtures/data/synthetic-rs256-private.pem. None is a real credential.\nuse crate::SecureQrInput;\n\n";
nr += `pub global N: u32 = ${N};\npub global SYNTHETIC_ISSUER_KEY_HASH: Field = ${SYNTHETIC_KEY_HASH};\n`;
nr += `/// UIDAI 2021 offline-QR modulus (certificate expired 2024-02-27), from anon-aadhaar@4dad918.\npub global UIDAI_2021_MODULUS: [Field; 18] = ${arr(rsaLimbs(Buffer.from(UIDAI_2021_MODULUS, "hex")))};\n`;
const records = {};
for (const [name, p] of Object.entries(prepared)) {
  const s = summary(p);
  records[name] = {
    note: synthetic[name]?.note ?? "upstream public test QR",
    signedSha256: createHash("sha256").update(p.signed).digest("hex"),
    ...s,
  };
  nr += `\npub global ${name.toUpperCase()}_ISSUED_AT: u64 = ${s.issued_at};\npub fn ${name}() -> SecureQrInput<N> {\n    ${input(p)}\n}\n`;
}
await writeFile(
  new URL("noir/aadhaar_secure_qr/src/vectors.nr", auth),
  nr,
);

// Example fixtures: policy is public input, the QR is private.
const TEST_KEY_HASH =
  "15134874015316324267425466444584014077184337590635665158241104437045239495873";
const issued = records.upstream.issued_at;
const document = (p, overrides = {}) => ({
  expected_issuer_key_hash: TEST_KEY_HASH,
  app_seed: "12345678",
  now: String(issued + 600),
  ...overrides,
  input: p.input,
});
const clone = (p) => JSON.parse(JSON.stringify(p));
const fixtures = {
  Prover: document(prepared.upstream),
  ProverFreshBoundary: document(prepared.upstream, {
    now: String(issued + 10800),
  }),
  ProverFutureBoundary: document(prepared.upstream, {
    now: String(issued - 900),
  }),
  ProverTooOld: document(prepared.upstream, { now: String(issued + 10801) }),
  ProverTooNew: document(prepared.upstream, { now: String(issued - 901) }),
  ProverWrongExpectedKey: document(prepared.upstream, {
    expected_issuer_key_hash:
      "18063425702624337643644061197836918910810808173893535653269228433734128853484",
  }),
};
{
  const p = clone(prepared.upstream);
  p.input.signature[0] = String(BigInt(p.input.signature[0]) ^ 1n);
  fixtures.ProverBadSignature = document(p);
}
{
  const p = clone(prepared.upstream);
  const dob = p.input.delimiters[3] + 1;
  p.input.signed_data.storage[dob + 9] = 0x33;
  fixtures.ProverAlteredBirthYear = document(p);
}
{
  const p = clone(prepared.upstream);
  p.input.modulus = prepared.s2032.input.modulus;
  p.input.redc = prepared.s2032.input.redc;
  fixtures.ProverWrongKey = document(p, {
    expected_issuer_key_hash: SYNTHETIC_KEY_HASH,
  });
}
fixtures.ProverYear2032 = document(prepared.s2032, {
  expected_issuer_key_hash: SYNTHETIC_KEY_HASH,
  now: String(records.s2032.issued_at + 600),
});
fixtures.ProverMaximalLeapDayMinor = document(prepared.maximal, {
  expected_issuer_key_hash: SYNTHETIC_KEY_HASH,
  now: String(records.maximal.issued_at + 600),
});
{
  // Skip the gender delimiter: every later hint moves up one place and the photo delimiter becomes the first 255 inside the photo.
  const p = clone(prepared.upstream);
  const s = p.input.signed_data.storage;
  const d = p.input.delimiters;
  let next = d[17] + 1;
  while (s[next] !== 255) next++;
  p.input.delimiters = [...d.slice(0, 5), ...d.slice(6), next];
  fixtures.ProverSkippedDelimiter = document(p);
}
{
  const p = clone(prepared.upstream);
  const d = p.input.delimiters;
  let next = d[17] + 1;
  const s = p.input.signed_data.storage;
  while (s[next] !== 255) next++;
  p.input.delimiters = [...d.slice(0, 17), next];
  fixtures.ProverPhotoDelimiterInPhoto = document(p);
}
{
  // Prover-chosen bytes after the signed length are outside the relation.
  const p = clone(prepared.upstream);
  const s = p.input.signed_data.storage;
  for (let i = p.input.signed_data.len; i < s.length; i++) s[i] = 255;
  fixtures.ProverTrailingGarbage = document(p);
}
{
  const p = clone(prepared.upstream);
  const len = p.input.signed_data.len;
  p.input.signed_data.storage[len] = 255;
  p.input.delimiters[17] = len;
  fixtures.ProverPhotoDelimiterAfterLength = document(p);
}
{
  // The ABI lets a prover set a length above the capacity N, which a Noir
  // test cannot build (BoundedVec::from_parts asserts len <= N).
  const p = clone(prepared.upstream);
  p.input.signed_data.len = N + 1;
  fixtures.ProverSignedLengthAboveCapacity = document(p);
}
// A 156-byte name: the signature, freshness and age checks pass; the
// nullifier rejects the name length.
fixtures.ProverLongNameNullifier = document(prepared.long_name, {
  expected_issuer_key_hash: SYNTHETIC_KEY_HASH,
  now: String(records.long_name.issued_at + 600),
});
const example = new URL("target/kat/aadhaar_secure_qr/", auth);
await mkdir(example, { recursive: true });
for (const [name, doc] of Object.entries(fixtures))
  await writeFile(new URL(`${name}.toml`, example), stringifyToml(doc));

const local = new URL(
  "fixtures/material/aadhaar_secure_qr/local-test/",
  auth,
);
await mkdir(local, { recursive: true });
await writeFile(
  new URL("synthetic-vectors.json", local),
  `${JSON.stringify({ warning: "Public synthetic test vectors only. The synthetic key and the upstream test key are published; never trust either issuer outside tests.", syntheticKey: "fixtures/data/synthetic-rs256-private.pem", vectors: records }, null, 2)}\n`,
);
console.log(
  JSON.stringify(
    Object.fromEntries(
      Object.entries(records).map(([k, v]) => [
        k,
        { issued_at: v.issued_at, length: v.length },
      ]),
    ),
  ),
);
