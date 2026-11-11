// Writes src/fixture.nr and fixtures/manifest.json for the Singpass
// attribute-gating instance: synthetic Singpass FAPI inner ID tokens (ES256)
// signed with the public local P-256 test scalars 42 and 43
// (scripts/fixtures/lib/local-p256-key.mjs, the key of the
// repository's local Singpass material). Each token is checked with the
// library's host importer (importVerifiedSingpass). None is a Singpass token.
//
// node scripts/fixtures/generators/singpass.mjs --instance attribute-gating/singpass \
//   --binding <field hex> --other-binding <field hex> [--now <unix s>]
//
// --binding is the caller binding that the instance test prints
// (`fixture_nonce_is_the_caller_binding`); --other-binding is the binding at
// the second shell contract. Needs `npm ci && npm run build` in
// packages/credential-proofs-inputs. No network access, no proving.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const credentials = "packages/credential-proofs-inputs";
const generator = "aztec/use-cases/scripts/fixtures/generators/singpass.mjs";
const load = (path) => import(pathToFileURL(repository + path).href);
// RFC 6979 deterministic ECDSA: node:crypto draws a random nonce, so a
// regenerated token would differ from the committed one.
const { p256 } = createRequire(import.meta.url)(
  "@noble/curves/p256",
);
const { localP256Key } = await load(
  "scripts/fixtures/lib/local-p256-key.mjs",
);
const { importVerifiedSingpass } = await import("credential-proofs-inputs/singpass");

const CAPACITY = {
  audience: 128,
  subject: 256,
  header: 256,
  payload: 1024,
  signature: 86,
};
const ISSUERS = {
  production: "https://id.singpass.gov.sg/fapi",
  staging: "https://stg-id.singpass.gov.sg/fapi",
};
// The official staging sample has exp - iat = 600 s; the tokens use it.
const LIFETIME = 600;
const AUDIENCE = "local-synthetic-singpass-client";
const SUBJECT = "local-synthetic-singpass-user";
const OTHER_SUBJECT = "local-synthetic-singpass-user-2";
const KID = "local-synthetic-singpass";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const field = (value) => {
  const hex = (value ?? "").replace(/^0x/, "").toLowerCase().padStart(64, "0");
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`not a field hex: ${value}`);
  return hex;
};
const array = (values) => {
  const lines = [];
  for (let i = 0; i < values.length; i += 16)
    lines.push(values.slice(i, i + 16).join(", "));
  return `[\n            ${lines.join(",\n            ")},\n        ]`;
};
const bounded = (bytes, capacity) => {
  if (bytes.length > capacity)
    throw new Error(`value of ${bytes.length} bytes exceeds ${capacity}`);
  return `BoundedVec::from_parts(${array([...bytes, ...new Array(capacity - bytes.length).fill(0)])}, ${bytes.length})`;
};

function signToken(scalar, claims) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const data = `${encode({ alg: "ES256", typ: "JWT", kid: KID })}.${encode(claims)}`;
  const secret = Buffer.alloc(32);
  secret[31] = scalar;
  const signature = Buffer.from(
    p256
      .sign(createHash("sha256").update(data).digest(), secret, { lowS: true })
      .toCompactRawBytes(),
  ).toString("base64url");
  return `${data}.${signature}`;
}

function jwk(scalar) {
  const key = localP256Key(scalar).key;
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(key.public_key_x).toString("base64url"),
    y: Buffer.from(key.public_key_y).toString("base64url"),
    alg: "ES256",
    use: "sig",
    kid: KID,
  };
}

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      binding: { type: "string" },
      "other-binding": { type: "string" },
      now: { type: "string", default: "4000000000" },
    },
  });
  if (values.instance !== "attribute-gating/singpass")
    throw new Error("Pass --instance attribute-gating/singpass");
  const binding = field(values.binding);
  const otherBinding = field(values["other-binding"]);
  const now = Number(values.now);
  if (!Number.isSafeInteger(now) || now < 3600)
    throw new Error("--now must be a Unix time in seconds");

  // name: [description, signing scalar, key scalar given to the circuit,
  // environment, claims overrides]
  const issuedAt = now - 60;
  const base = (environment, nonce, subject, iat, acr) => ({
    iss: ISSUERS[environment],
    aud: AUDIENCE,
    sub: subject,
    nonce,
    iat,
    exp: iat + LIFETIME,
    sub_type: "user",
    acr: `urn:singpass:authentication:loa:${acr}`,
    amr: ["pwd", "swk"],
    sub_attributes: { name: "SYNTHETIC LOCAL TEST" },
  });
  const tokens = {
    token: [
      "the valid token: production, assurance 2, bound to this caller",
      42,
      "production",
      base("production", binding, SUBJECT, issuedAt, 2),
    ],
    second_token: [
      "a second login of the same subject, 30 s later",
      42,
      "production",
      base("production", binding, SUBJECT, issuedAt + 30, 2),
    ],
    other_subject: [
      "another subject at the same client",
      42,
      "production",
      base("production", binding, OTHER_SUBJECT, issuedAt, 2),
    ],
    assurance_3: [
      "the same subject at assurance 3",
      42,
      "production",
      base("production", binding, SUBJECT, issuedAt + 10, 3),
    ],
    staging: [
      "a staging token at assurance 1",
      42,
      "staging",
      base("staging", binding, SUBJECT, issuedAt, 1),
    ],
    other_key: [
      "a token signed with the other local key (scalar 43)",
      43,
      "production",
      base("production", binding, SUBJECT, issuedAt, 2),
    ],
    other_contract: [
      "a token bound to the caller at the second contract",
      42,
      "production",
      base("production", otherBinding, SUBJECT, issuedAt, 2),
    ],
  };

  const header = `//! Generated by scripts/fixtures/generators/singpass.mjs; see fixtures/manifest.json. Do not edit.
//! Synthetic Singpass FAPI inner ID tokens signed with the public local P-256
//! test scalars 42 and 43. None is a Singpass token.
use uc_adapter_singpass::SingpassIdToken;

/// The verifier time the tokens were made for.
pub global NOW: u64 = ${now};
/// The signed \`iat\` and exclusive \`exp\` of \`token()\` (\`exp - iat\` is
/// ${LIFETIME} s, as in the official staging sample).
pub global ISSUED_AT: u64 = ${issuedAt};
pub global EXPIRY: u64 = ${issuedAt + LIFETIME};
/// The caller binding that every token except \`other_contract()\` carries
/// as its nonce, and the binding at the second contract.
pub global BINDING: Field = 0x${binding};
pub global OTHER_BINDING: Field = 0x${otherBinding};

/// The public key of local test scalar 43 (no token in the tests verifies
/// under it except \`other_key()\`).
pub global OTHER_KEY_X: [u8; 32] = ${array(localP256Key(43).key.public_key_x).replace(/\n {8}/g, "\n")};
pub global OTHER_KEY_Y: [u8; 32] = ${array(localP256Key(43).key.public_key_y).replace(/\n {8}/g, "\n")};
`;
  let body = "";
  const claims = {};
  for (const [
    name,
    [description, scalar, environment, payload],
  ] of Object.entries(tokens)) {
    const token = signToken(scalar, payload);
    // The library's host importer checks the signature and the claims.
    await importVerifiedSingpass(
      token,
      {
        environment,
        minimumAssurance: environment === "production" ? 2 : 1,
        audience: AUDIENCE,
        subject: payload.sub,
        nonce: payload.nonce,
        now,
      },
      jwk(scalar),
    );
    const [h, p, s] = token.split(".");
    const key = localP256Key(scalar).key;
    claims[name] = payload;
    body += `
/// ${description[0].toUpperCase()}${description.slice(1)}.
pub fn ${name}() -> SingpassIdToken {
    SingpassIdToken {
        public_key_x: ${array(key.public_key_x)},
        public_key_y: ${array(key.public_key_y)},
        environment: ${environment === "production" ? 0 : 1},
        audience: ${bounded(Buffer.from(AUDIENCE), CAPACITY.audience)},
        subject: ${bounded(Buffer.from(payload.sub), CAPACITY.subject)},
        header_b64: ${bounded(Buffer.from(h, "ascii"), CAPACITY.header)},
        payload_b64: ${bounded(Buffer.from(p, "ascii"), CAPACITY.payload)},
        signature_b64: ${bounded(Buffer.from(s, "ascii"), CAPACITY.signature)},
    }
}
`;
  }
  const fixture = formatNoir(header + body);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const inputs = {};
  for (const path of [
    "scripts/fixtures/lib/local-p256-key.mjs",
    `${credentials}/src/singpass.ts`,
    `${credentials}/src/es256.ts`,
    generator,
  ]) {
    inputs[path] = sha256(await readFile(repository + path));
  }
  const record = {
    schema: "uc-fixture-v1",
    scheme: "singpass",
    use_case: "attribute-gating",
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/singpass.mjs",
        "--instance",
        values.instance,
        "--binding",
        binding,
        "--other-binding",
        otherBinding,
        "--now",
        String(now),
      ],
      cwd: "aztec/use-cases",
      library: `@noble/curves p256 ES256 (RFC 6979, low s), checked with ${credentials}/src/singpass.ts importVerifiedSingpass`,
    },
    inputs,
    key_provenance:
      "Public local P-256 test scalars 42 and 43 (scripts/fixtures/lib/local-p256-key.mjs); not a Singpass key. Anyone can sign with them.",
    claims,
    notes: [
      "The bindings are the instance's caller bindings observed in TXE; the instance test fails with the values to use when they change.",
      `iat is 60 s before --now (second_token 30 s and assurance_3 50 s before) and exp - iat is ${LIFETIME} s.`,
      "Variants are separately signed tokens; tampering cases mutate a valid token in src/test.nr.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(`Wrote ${values.instance}/src/fixture.nr for binding ${binding}`);
}

await main();
