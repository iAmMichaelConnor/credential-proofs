// Writes src/fixture.nr and fixtures/manifest.json for an RS256 or ES256
// OIDC instance from a public synthetic test key (packages/credential-proofs-inputs).
// The token is synthetic: it is not a provider credential.
//
// node scripts/fixtures/generators/oidc.mjs --instance login-link/google --nonce <field hex> [--now <unix s>]
//
// The nonce is the value the instance binds (for a login link, the
// challenge that the instance test prints). A provider without a nonce
// claim (LinkedIn) takes no --nonce. Needs `npm ci && npm run build` in
// packages/credential-proofs-inputs. No network access, no proving.
//
// An attribute-gating instance (a profile with `attribute`) takes the two
// caller bindings that its test `fixture_nonce_is_the_caller_binding`
// prints instead of --nonce:
// node scripts/fixtures/generators/oidc.mjs --instance attribute-gating/govbr --binding <hex> --other-binding <hex> [--now <unix s>]
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { formatNoir } from "./nr_format.mjs";

const project = fileURLToPath(new URL("../../../", import.meta.url));
const repository = fileURLToPath(new URL("../../../../../", import.meta.url));
const credentials = "packages/credential-proofs-inputs";
// Dependencies are declared by aztec/use-cases/package.json.
const credentialsRequire = createRequire(
  import.meta.url,
);
const RS2048 = {
  bits: 2048,
  privatePem: `fixtures/data/synthetic-rs256-private.pem`,
  publicPem: `fixtures/data/synthetic-rs256-public.pem`,
  kid: "local-synthetic-rs256",
};
const RS4096 = {
  bits: 4096,
  privatePem: `fixtures/data/rsa-signature/rsa4096-test-private.pem`,
  kid: "local-synthetic-linkedin-rs256-4096",
};
// The public synthetic P-256 test scalars: 42 signs the fixture tokens
// (packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts), 43 is the other key.
const P256 = { kind: "p256", scalar: 42, otherScalar: 43 };
const ES256_CAPACITIES = { header: 192, payload: 1024, signature: 86 };
const FLAT = {
  audience: 128,
  subject: 256,
  header: 128,
  payload: 1024,
  signature: 344,
};
const TENANT = "12345678-1234-1234-1234-123456789abc";
const CAMPUS_IDP = "https://idp.example.edu/idp/shibboleth";
// The signed CILogon `affiliation` of the attribute-gate fixture and the
// entry that its input presents.
const CAMPUS_AFFILIATION = "member@example.edu;student@example.edu";
const AFFILIATION = "student@example.edu";
// The gov.br `reliability_info` of createSyntheticGovbr at `level`.
const govbrReliability = (level) => ({
  level,
  reliabilities: [
    { id: "601", updatedAt: "2025-07-02T14:17:16.001-0300" },
    { id: "626" },
  ],
});
// One profile per adapter input type. `lifetime` is exp - iat of the
// token: the provider's documented lifetime where it publishes one, else a
// synthetic choice. Every adapter reads the signed iat. `fields` are
// the provider-specific struct fields
// written between the key and the audience (null: the campus idp; a
// function: its value for the fixture context).
// `importer` names the credentials module whose importer checks the
// signed token before it is written.
const profiles = {
  GoogleIdToken: {
    provider: "google",
    issuer: "https://accounts.google.com",
    lifetime: 3600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  AppleIdToken: {
    provider: "apple",
    issuer: "https://appleid.apple.com",
    lifetime: 600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  FacebookIdToken: {
    provider: "facebook",
    issuer: "https://www.facebook.com",
    lifetime: 3600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  TelegramIdToken: {
    provider: "telegram",
    issuer: "https://oauth.telegram.org",
    lifetime: 3600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  KakaoIdToken: {
    provider: "kakao",
    issuer: "https://kauth.kakao.com",
    lifetime: 3600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  MiArgentinaIdToken: {
    provider: "miargentina",
    issuer: "https://id.argentina.gob.ar",
    lifetime: 3600,
    capacities: FLAT,
    key: RS2048,
    importer: "oidc",
  },
  EntraIdToken: {
    provider: "entra",
    issuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    lifetime: 3600,
    capacities: {
      audience: 128,
      subject: 256,
      header: 256,
      payload: 2048,
      signature: 344,
    },
    key: RS2048,
    importer: "entra",
    extraClaims: { tid: TENANT, ver: "2.0" },
    fields: [["tenant", `[${[...Buffer.from(TENANT, "ascii")].join(", ")}]`]],
    // The attribute gate: the tenant, fixed by the signed issuer.
    attribute: { claims: {}, variants: {} },
  },
  GovbrIdToken: {
    provider: "govbr",
    issuer: "https://sso.acesso.gov.br/",
    lifetime: 60,
    capacities: {
      audience: 128,
      subject: 256,
      header: 128,
      payload: 2048,
      signature: 344,
    },
    key: RS2048,
    importer: "govbr",
    // The claim shape of createSyntheticGovbr, with signed assurance gold.
    extraClaims: {
      amr: ["passwd", "mfa", "otp_offline"],
      scope: ["openid", "govbr_confiabilidades_idtoken"],
      reliability_info: {
        level: "gold",
        reliabilities: [
          { id: "601", updatedAt: "2025-07-02T14:17:16.001-0300" },
          { id: "626" },
        ],
      },
    },
    fields: [
      ["staging", "false"],
      ["minimum_level", "2"],
    ],
    defaults: { subject: "12345678909" },
    // gov.br tokens live 60 s; sign the token 30 s before --now.
    age: 30,
    // The attribute gate: the signed assurance rank. The base token
    // is silver (rank 2), the pinned library floor.
    attribute: {
      claims: { reliability_info: govbrReliability("silver") },
      variants: {
        level_gold: [
          "the same subject at gold (rank 3), 10 s later",
          10,
          { reliability_info: govbrReliability("gold") },
          { minimumLevel: "silver" },
        ],
        level_bronze: [
          "the same subject at bronze (rank 1), below the pinned floor, 10 s later",
          10,
          { reliability_info: govbrReliability("bronze") },
          { minimumLevel: "bronze" },
        ],
      },
    },
  },
  UniversityIdToken: {
    provider: "university",
    issuer: "https://cilogon.org",
    lifetime: 900,
    capacities: {
      audience: 128,
      subject: 256,
      header: 256,
      payload: 2048,
      signature: 344,
    },
    key: RS2048,
    importer: "university",
    extraClaims: { idp: CAMPUS_IDP },
    fields: [["institutional_idp", null]],
    defaults: { subject: "http://cilogon.org/serverA/users/100001" },
    // The attribute gate takes UniversityAffiliationToken: the token
    // and one entry of its signed semicolon-delimited `affiliation`.
    attribute: {
      claims: { affiliation: CAMPUS_AFFILIATION },
      wrap: {
        field: "token",
        extra: [["affiliation", Buffer.from(AFFILIATION, "utf8"), 128]],
      },
      variants: {
        no_affiliation: [
          "the same subject without an affiliation claim, 10 s later",
          10,
          { affiliation: undefined },
          {},
        ],
      },
    },
  },
  LinkedInIdToken: {
    provider: "linkedin",
    issuer: "https://www.linkedin.com",
    // LinkedIn publishes no lifetime. The adapter reads the signed iat, and
    // a one-day token shows the 4-hour bearer ceiling before expiry.
    lifetime: 86400,
    noNonce: true,
    capacities: {
      audience: 256,
      subject: 256,
      header: 256,
      payload: 2048,
      signature: 684,
    },
    key: RS4096,
    importer: "linkedin",
  },
  LineIdToken: {
    provider: "line",
    issuer: "https://access.line.me",
    // A synthetic choice (the LINE account fixture uses one hour).
    lifetime: 3600,
    capacities: { audience: 32, subject: 256, ...ES256_CAPACITIES },
    key: P256,
    kid: "synthetic-line-key",
    importer: "line",
    extraClaims: { amr: ["lineautologin"] },
    defaults: {
      audience: "1234567890",
      subject: "U0123456789abcdef0123456789abcdef",
    },
  },
  FranceConnectIdToken: {
    provider: "franceconnect",
    issuer: "https://auth.franceconnect.gouv.fr/api/v2",
    // A synthetic choice (the FranceConnect+ account fixture uses 120 s).
    lifetime: 120,
    capacities: { audience: 128, subject: 256, ...ES256_CAPACITIES },
    key: P256,
    kid: "repository-synthetic-p256",
    importer: "franceconnect",
    extraClaims: { acr: "eidas2", amr: ["fc", "pwd"] },
    fields: [
      ["integration", "false"],
      ["minimum_acr", "2"],
    ],
    defaults: { subject: "synthetic-pairwise-service-subject" },
    attribute: {
      claims: {},
      wrap: { field: "token", extra: [] },
      variants: {
        assurance_3: [
          "the same subject with signed eidas3 and configured minimum2,10s later",
          10,
          { acr: "eidas3" },
          {},
        ],
      },
    },
  },
  SingpassIdToken: {
    provider: "singpass",
    issuer: "https://id.singpass.gov.sg/fapi",
    // The official staging sample has exp - iat = 600 s.
    lifetime: 600,
    capacities: {
      audience: 128,
      subject: 256,
      ...ES256_CAPACITIES,
      header: 256,
    },
    key: P256,
    kid: "local-synthetic-singpass",
    importer: "singpass",
    // The claim shape of scripts/fixtures/generators/singpass.mjs, assurance 2.
    extraClaims: {
      sub_type: "user",
      acr: "urn:singpass:authentication:loa:2",
      amr: ["pwd", "swk"],
      sub_attributes: { name: "SYNTHETIC LOCAL TEST" },
    },
    fields: [["environment", "0"]],
    defaults: { subject: "local-synthetic-singpass-user" },
  },
};
// The token is signed this long before the verifier time, unless the
// profile sets `age`.
const AGE = 60;

// An RSA key derived from a public seed by x509.py seeded_key (Python
// cryptography), so no key is stored and anyone can regenerate it.
function seededPem(label, bits) {
  const script = `import sys; sys.path.insert(0, ${JSON.stringify(project + "scripts/fixtures/generators")}); import x509
from cryptography.hazmat.primitives import serialization
k = x509.seeded_key(${JSON.stringify(label)}, ${bits})
sys.stdout.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())`;
  return execFileSync("python3", ["-c", script], { encoding: "utf8" });
}

const modulusOf = (pem) =>
  BigInt(
    `0x${Buffer.from(createPublicKey(createPrivateKey(pem)).export({ format: "jwk" }).n, "base64url").toString("hex")}`,
  );

// The other key of the wrong-key tests: a real key pair of the same
// size whose modulus exceeds the fixture key's, so the fixture signature
// (below the fixture modulus) is also below the other modulus and passes
// the field check under it. The first seed label v1, v2, ... that gives
// such a modulus is used; the label is recorded in the manifest.
function otherKey(bits, fixtureModulus) {
  for (let version = 1; version < 64; version++) {
    const label = `uc login-link other rs256-${bits} key v${version}`;
    const privatePem = seededPem(label, bits);
    if (modulusOf(privatePem) > fixtureModulus) return { label, privatePem };
  }
  throw new Error("no seeded key with a larger modulus");
}

const signRs256 = (signingInput, privatePem) =>
  createSign("RSA-SHA256")
    .update(signingInput, "ascii")
    .sign(privatePem)
    .toString("base64url");

async function trustedJwk(key) {
  const privatePem = await readFile(`${repository}${key.privatePem}`, "utf8");
  const publicKey = key.publicPem
    ? createPublicKey(await readFile(`${repository}${key.publicPem}`, "utf8"))
    : createPublicKey(createPrivateKey(privatePem));
  return {
    privatePem,
    jwk: {
      ...publicKey.export({ format: "jwk" }),
      kid: key.kid,
      alg: "RS256",
      use: "sig",
    },
  };
}

// A P-256 key of a public test scalar, and its deterministic ES256 signer:
// RFC 6979 with high s allowed, as signSyntheticEs256 does.
function p256Signer(scalar, kid) {
  const { p256 } = credentialsRequire("@noble/curves/p256");
  const secret = Buffer.alloc(32);
  secret[31] = scalar;
  const point = Buffer.from(p256.getPublicKey(secret, false));
  return {
    x: [...point.subarray(1, 33)],
    y: [...point.subarray(33, 65)],
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: point.subarray(1, 33).toString("base64url"),
      y: point.subarray(33, 65).toString("base64url"),
      alg: "ES256",
      use: "sig",
      kid,
    },
    sign: (signingInput) =>
      Buffer.from(
        p256
          .sign(createHash("sha256").update(signingInput).digest(), secret, {
            lowS: false,
          })
          .toCompactRawBytes(),
      ).toString("base64url"),
  };
}

// The fixture key and the other key of the wrong-key tests, with the
// fixture text that names them.
async function keyMaterial(profile) {
  if (profile.key.kind === "p256") {
    const signer = p256Signer(profile.key.scalar, profile.kid);
    const other = p256Signer(profile.key.otherScalar, profile.kid);
    return {
      signer,
      other,
      fields: `        public_key_x: ${array(signer.x)},
        public_key_y: ${array(signer.y)},
`,
      globals: `/// Another P-256 public key: the public test scalar ${profile.key.otherScalar}.
pub global OTHER_KEY_X: [u8; 32] = ${array(other.x).replace(/\n {8}/g, "\n")};
pub global OTHER_KEY_Y: [u8; 32] = ${array(other.y).replace(/\n {8}/g, "\n")};
`,
      summary: `the public synthetic P-256 test scalar ${profile.key.scalar}\n//! (packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts)`,
      library: `packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts signSyntheticEs256 (P-256 scalar ${profile.key.scalar}, RFC 6979)`,
      provenance: `Public synthetic P-256 scalars ${profile.key.scalar} (fixture key, packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts) and ${profile.key.otherScalar} (other key); not a ${profile.provider} key. Anyone can sign with them.`,
      otherNote: `other_key_signature() signs the fixture token under the public test scalar ${profile.key.otherScalar}`,
      inputs: [
        `packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts`,
        `${credentials}/src/${profile.importer}.ts`,
        `${credentials}/src/es256.ts`,
      ],
    };
  }
  const { privatePem, jwk } = await trustedJwk(profile.key);
  const bits = profile.key.bits;
  const { rsaKeyToCircuit } = await import(
    `credential-proofs-inputs/oidc`
  );
  const trusted = rsaKeyToCircuit(jwk, bits);
  const join = (parts) =>
    parts.reduceRight((acc, limb) => (acc << 120n) + BigInt(limb), 0n);
  const otherPem = otherKey(bits, join(trusted.modulus_limbs));
  const otherJwk = {
    ...createPublicKey(createPrivateKey(otherPem.privatePem)).export({
      format: "jwk",
    }),
    kid: jwk.kid,
    alg: "RS256",
    use: "sig",
  };
  const otherTrusted = rsaKeyToCircuit(otherJwk, bits);
  const limbCount = trusted.modulus_limbs.length;
  const limbs = (values) => array(values.map(String));
  return {
    signer: { jwk, sign: (input) => signRs256(input, privatePem) },
    other: {
      jwk: otherJwk,
      sign: (input) => signRs256(input, otherPem.privatePem),
    },
    fields: `        modulus_limbs: ${limbs(trusted.modulus_limbs)},
        redc_params_limbs: ${limbs(trusted.redc_params_limbs)},
`,
    globals: `/// Another ${bits}-bit RSA key (modulus and Barrett parameters), derived by
/// x509.py seeded_key from the public seed label
/// "${otherPem.label}". Its modulus exceeds the fixture key's.
pub global OTHER_MODULUS_LIMBS: [u128; ${limbCount}] = ${limbs(otherTrusted.modulus_limbs).replace(/\n {8}/g, "\n")};
pub global OTHER_REDC_PARAMS_LIMBS: [u128; ${limbCount}] = ${limbs(otherTrusted.redc_params_limbs).replace(/\n {8}/g, "\n")};
`,
    summary:
      bits === 2048
        ? "the public synthetic RS256 test\n//! key"
        : `the public RSA-${bits} test\n//! key`,
    summarySuffix: ` in fixtures/data`,
    library: `${credentials}/src/${profile.importer}.ts ${IMPORTERS[profile.importer]} (signed with node:crypto)`,
    provenance: `Public ${bits === 2048 ? "synthetic RS256" : `RSA-${bits}`} test key committed in fixtures/data; not a ${profile.provider} key. Anyone can sign with it.`,
    otherNote: `other_key_signature() signs the fixture token under the key from the seed label '${otherPem.label}' (x509.py seeded_key), whose modulus exceeds the fixture key's`,
    inputs: [
      profile.key.privatePem,
      ...(profile.key.publicPem ? [profile.key.publicPem] : []),
      `${credentials}/src/${profile.importer}.ts`,
      ...(profile.importer === "oidc" ? [] : [`${credentials}/src/oidc.ts`]),
    ],
  };
}

// Signs the token here, because the library's synthetic helpers fix
// exp - iat; main() checks it with the library's importer.
function signWith(profile, expected, issuedAt, expiry, signer, overrides = {}) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  const claims = {
    ...(profile.noNonce ? {} : { nonce: expected.nonce }),
    iss: profile.issuer,
    aud: expected.audience,
    sub: expected.subject,
    iat: issuedAt,
    exp: expiry,
    ...(profile.extraClaims ?? {}),
    ...overrides,
  };
  // The ES256 header is the one signSyntheticEs256 writes.
  const header = profile.key.kind === "p256"
    ? { alg: "ES256", typ: "JWT", kid: signer.jwk.kid }
    : { alg: "RS256", kid: signer.jwk.kid, typ: "JWT" };
  const signingInput = `${encode(header)}.${encode(claims)}`;
  return `${signingInput}.${signer.sign(signingInput)}`;
}

const IMPORTERS = {
  oidc: "importVerifiedOidc",
  line: "importVerifiedLine",
  franceconnect: "importVerifiedFranceConnect",
  singpass: "importVerifiedSingpass",
  entra: "importVerifiedEntra",
  govbr: "importVerifiedGovbr",
  university: "importVerifiedUniversity",
  linkedin: "importVerifiedLinkedIn",
};

// The library's own checks of the signed token (signature, issuer,
// audience, subject, nonce, times and the provider-specific claims).
async function check(profile, token, expected, jwk) {
  const module = await import(
    `credential-proofs-inputs/${profile.importer}`
  );
  const verify = module[IMPORTERS[profile.importer]];
  switch (profile.importer) {
    case "oidc":
      return verify(profile.provider, token, expected, jwk);
    case "entra":
      return verify(token, { ...expected, tenant: TENANT }, jwk);
    case "govbr":
      return verify(
        token,
        {
          ...expected,
          environment: "production",
          minimumLevel: expected.minimumLevel ?? "silver",
        },
        jwk,
      );
    case "university":
      return verify(
        token,
        {
          ...expected,
          mode: "cilogon",
          issuer: profile.issuer,
          institutionalIdp: CAMPUS_IDP,
        },
        jwk,
      );
    case "line":
      return verify(token, expected, jwk);
    case "franceconnect":
      return verify(
        token,
        { ...expected, environment: "production", minimumAcr: 2 },
        jwk,
      );
    case "singpass":
      return verify(
        token,
        { ...expected, environment: "production", minimumAssurance: 2 },
        jwk,
      );
    case "linkedin":
      return verify(
        token,
        {
          audience: expected.audience,
          subject: expected.subject,
          now: expected.now,
        },
        jwk,
      );
    default:
      throw new Error(`no importer ${profile.importer}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function bounded(bytes, capacity) {
  if (bytes.length > capacity)
    throw new Error(`value of ${bytes.length} bytes exceeds ${capacity}`);
  const storage = [...bytes, ...new Array(capacity - bytes.length).fill(0)];
  return `BoundedVec::from_parts(${array(storage)}, ${bytes.length})`;
}

function array(values) {
  const lines = [];
  for (let i = 0; i < values.length; i += 16)
    lines.push(values.slice(i, i + 16).join(", "));
  return `[\n            ${lines.join(",\n            ")},\n        ]`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      instance: { type: "string" },
      nonce: { type: "string" },
      binding: { type: "string" },
      "other-binding": { type: "string" },
      now: { type: "string", default: "4000000000" },
      audience: { type: "string" },
      subject: { type: "string" },
    },
  });
  if (!values.instance) throw new Error("Pass --instance <use-case>/<scheme>");
  const manifest = JSON.parse(
    await readFile(project + "use-cases.json", "utf8"),
  );
  const [useCase, scheme] = values.instance.split("/");
  const instance = manifest.instances.find(
    (i) => i.use_case === useCase && i.scheme === scheme,
  );
  if (!instance) throw new Error(`${values.instance} is not in use-cases.json`);
  const adapter = manifest.adapters[instance.adapter];
  const input = adapter?.input;
  if (adapter?.family !== "oidc" || !(input in profiles)) {
    throw new Error(`${values.instance}: no OIDC fixture shape for ${input}`);
  }
  const profile = profiles[input];
  if (useCase === "attribute-gating") {
    if (!profile.attribute)
      throw new Error(`${values.instance}: ${input} has no attribute profile`);
    return attributeFixture(values, scheme, useCase, adapter, profile);
  }
  values.subject ??= profile.defaults?.subject ?? "100000000000000000001";
  values.audience ??=
    profile.defaults?.audience ?? "credential-proofs-use-case-client";
  let nonce = "";
  if (profile.noNonce) {
    if (values.nonce !== undefined)
      throw new Error(`${input} tokens carry no nonce; omit --nonce`);
  } else {
    // Accept a Field as the instance test prints it (0x..., not zero-padded).
    nonce = (values.nonce ?? "")
      .replace(/^0x/, "")
      .toLowerCase()
      .padStart(64, "0");
    if (!/^[0-9a-f]{64}$/.test(nonce))
      throw new Error("Pass --nonce <field as hex>");
  }
  const now = Number(values.now);
  if (!Number.isSafeInteger(now) || now < 86400)
    throw new Error("--now must be a Unix time in seconds");
  const expected = {
    audience: values.audience,
    subject: values.subject,
    nonce,
    now,
  };
  const age = profile.age ?? AGE;
  const keys = await keyMaterial(profile);
  const token = signWith(
    profile,
    expected,
    now - age,
    now - age + profile.lifetime,
    keys.signer,
  );
  await check(profile, token, expected, keys.signer.jwk);
  const [header, payload, signature] = token.split(".");
  if (profile.key.kind === "p256") {
    // The fixture token is the library's own synthetic ES256 token.
    const { signSyntheticEs256Raw } = await import(
      `credential-proofs-test-builders/synthetic-es256`
    );
    const json = Buffer.from(payload, "base64url").toString("utf8");
    if (signSyntheticEs256Raw(json, profile.kid) !== token)
      throw new Error("ES256 token differs from signSyntheticEs256");
  }
  // A second token under the fixture key with the same exp
  // and an iat one second later (another payload), and the fixture token's
  // signing input signed under the other key. The importer checks both.
  const later = signWith(
    profile,
    expected,
    now - age + 1,
    now - age + profile.lifetime,
    keys.signer,
  );
  await check(profile, later, expected, keys.signer.jwk);
  const [, laterPayload, laterSignature] = later.split(".");
  const otherKeySignature = keys.other.sign(`${header}.${payload}`);
  await check(
    profile,
    `${header}.${payload}.${otherKeySignature}`,
    expected,
    keys.other.jwk,
  );
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  const size = profile.capacities;
  const fields = (profile.fields ?? [])
    .map(
      ([name, value]) =>
        `        ${name}: ${
          value === null
            ? bounded(Buffer.from(CAMPUS_IDP, "utf8"), 256)
            : typeof value === "function"
              ? value({ now, bounded })
              : value
        },\n`,
    )
    .join("");
  const lifetimeDoc = `/// The signed \`iat\` and exclusive \`exp\` (\`exp - iat\` = ${profile.lifetime} s; the adapter
/// reads the signed \`iat\`).`;
  const nonceDoc = profile.noNonce
    ? ""
    : `/// The value whose hex the token carries as its nonce.
pub global NONCE: Field = 0x${nonce};
`;
  const unformatted = `//! Generated by scripts/fixtures/generators/oidc.mjs; see fixtures/manifest.json. Do not edit.
//! A synthetic ${profile.provider} ID token signed with ${keys.summary}${keys.summarySuffix ?? ""}. It is not a provider credential.
use ${adapter.crate}::${input};

/// The verifier time the token was made for.
pub global NOW: u64 = ${now};
${lifetimeDoc}
pub global ISSUED_AT: u64 = ${claims.iat};
pub global EXPIRY: u64 = ${claims.exp};
${nonceDoc}
${keys.globals}
/// The fixture token's \`header.payload\` signed under the other key.
pub fn other_key_signature() -> BoundedVec<u8, ${size.signature}> {
    ${bounded(Buffer.from(otherKeySignature, "ascii"), size.signature)}
}

/// The payload of a second token under the fixture key (the same \`exp\`,
/// \`iat\` one second later), and its signature.
pub fn later_payload() -> BoundedVec<u8, ${size.payload}> {
    ${bounded(Buffer.from(laterPayload, "ascii"), size.payload)}
}
pub fn later_signature() -> BoundedVec<u8, ${size.signature}> {
    ${bounded(Buffer.from(laterSignature, "ascii"), size.signature)}
}

pub fn token() -> ${input} {
    ${input} {
${keys.fields}${fields}        audience: ${bounded(Buffer.from(values.audience, "utf8"), size.audience)},
        subject: ${bounded(Buffer.from(values.subject, "utf8"), size.subject)},
        header_b64: ${bounded(Buffer.from(header, "ascii"), size.header)},
        payload_b64: ${bounded(Buffer.from(payload, "ascii"), size.payload)},
        signature_b64: ${bounded(Buffer.from(signature, "ascii"), size.signature)},
    }
}
`;
  const fixture = formatNoir(unformatted);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const inputs = {};
  for (const path of [
    ...keys.inputs,
    "aztec/use-cases/scripts/fixtures/generators/oidc.mjs",
    ...(profile.key.kind === "p256"
      ? []
      : ["aztec/use-cases/scripts/fixtures/generators/x509.py"]),
  ]) {
    inputs[path] = sha256(await readFile(repository + path));
  }
  const argv = [
    "node",
    "scripts/fixtures/generators/oidc.mjs",
    "--instance",
    values.instance,
  ];
  if (!profile.noNonce) argv.push("--nonce", nonce);
  argv.push(
    "--now",
    String(now),
    "--audience",
    values.audience,
    "--subject",
    values.subject,
  );
  const record = {
    schema: "uc-fixture-v1",
    scheme,
    use_case: useCase,
    kind: "synthetic",
    generator: {
      argv,
      cwd: "aztec/use-cases",
      library: keys.library,
    },
    inputs,
    key_provenance: keys.provenance,
    claims,
    notes: [
      profile.noNonce
        ? "The provider's ID tokens carry no nonce, so the fixture binds no challenge (bearer)."
        : "The nonce is the instance's bound value observed in TXE; the instance test fails with the value to use when it changes.",
      `iat is ${age} s before --now; the adapter reads the signed iat, and exp - iat is ${profile.lifetime} s.`,
      `later_payload() is the same claims with iat one second later and the same exp, signed by the fixture key; ${keys.otherNote}. The importer checks both tokens.`,
      "Negative cases mutate this fixture in src/test.nr.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(
    `Wrote ${values.instance}/src/fixture.nr` +
      (nonce ? ` for nonce ${nonce}` : ""),
  );
}

// The fixture of an attribute-gating instance: tokens bound to the
// caller bindings that the instance test prints, under the fixture key, with
// the attribute claims of `profile.attribute`. Variants share the key, the
// audience and the header with `token()` and replace the payload and the
// signature (and the subject where it changes).
async function attributeFixture(values, scheme, useCase, adapter, profile) {
  const input = adapter.input;
  const type = adapter.types?.[useCase] ?? input;
  const attribute = profile.attribute;
  if (profile.noNonce)
    throw new Error(
      `${values.instance}: attribute fixtures require a signed nonce`,
    );
  if (values.nonce !== undefined)
    throw new Error("An attribute gate takes --binding and --other-binding");
  const field = (value, name) => {
    if (value === undefined) throw new Error(`Pass --${name} <field as hex>`);
    const hex = value.replace(/^0x/, "").toLowerCase().padStart(64, "0");
    if (!/^[0-9a-f]{64}$/.test(hex))
      throw new Error(`Pass --${name} <field as hex>`);
    return hex;
  };
  const binding = field(values.binding, "binding");
  const otherBinding = field(values["other-binding"], "other-binding");
  const now = Number(values.now);
  if (!Number.isSafeInteger(now) || now < 86400)
    throw new Error("--now must be a Unix time in seconds");
  const subject =
    values.subject ?? profile.defaults?.subject ?? "100000000000000000001";
  const otherSubject = `${subject}2`;
  const audience =
    values.audience ??
    profile.defaults?.audience ??
    "credential-proofs-use-case-client";
  const age = profile.age ?? AGE;
  const issuedAt = now - age;
  const expiry = issuedAt + profile.lifetime;
  const keys = await keyMaterial(profile);
  const size = profile.capacities;
  const expectedFor = (nonce, sub, extra = {}) => ({
    audience,
    subject: sub,
    nonce,
    now,
    ...extra,
  });
  // name: [description, iat offset, subject, nonce, claim overrides, check overrides]
  const tokens = {
    token: [
      "the valid token, bound to this caller",
      0,
      subject,
      binding,
      {},
      {},
    ],
    second_token: [
      "a second login of the same subject, 1 s later (the same exp)",
      1,
      subject,
      binding,
      {},
      {},
    ],
    other_subject: [
      "another subject at the same client",
      0,
      otherSubject,
      binding,
      {},
      {},
    ],
    other_contract: [
      "the same subject bound to the caller at the second contract",
      0,
      subject,
      otherBinding,
      {},
      {},
    ],
  };
  for (const [name, [description, offset, overrides, check]] of Object.entries(
    attribute.variants,
  ))
    tokens[name] = [description, offset, subject, binding, overrides, check];
  const signed = {};
  const claims = {};
  for (const [name, [, offset, sub, nonce, overrides, extra]] of Object.entries(
    tokens,
  )) {
    const expected = expectedFor(nonce, sub, extra);
    const token = signWith(
      profile,
      expected,
      issuedAt + offset,
      expiry,
      keys.signer,
      { ...attribute.claims, ...overrides },
    );
    await check(profile, token, expected, keys.signer.jwk);
    const [header, payload, signature] = token.split(".");
    signed[name] = { header, payload, signature };
    claims[name] = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    );
    if (name === "token" && profile.importer === "university") {
      const { assertAssertedUniversityAffiliation } = await import(
        `credential-proofs-inputs/university`
      );
      assertAssertedUniversityAffiliation(
        claims[name],
        AFFILIATION,
        "cilogon-semicolon",
      );
    }
  }
  const base = signed.token;
  if (Object.values(signed).some((t) => t.header !== base.header))
    throw new Error("variant headers differ");
  // The fixture token's signing input under the other key.
  const otherKeySignature = keys.other.sign(`${base.header}.${base.payload}`);
  await check(
    profile,
    `${base.header}.${base.payload}.${otherKeySignature}`,
    expectedFor(binding, subject),
    keys.other.jwk,
  );
  const fields = (profile.fields ?? [])
    .map(
      ([name, value]) =>
        `        ${name}: ${
          value === null
            ? bounded(Buffer.from(CAMPUS_IDP, "utf8"), 256)
            : typeof value === "function"
              ? value({ now, bounded })
              : value
        },\n`,
    )
    .join("");
  const inner = `${input} {
${keys.fields}${fields}        audience: ${bounded(Buffer.from(audience, "utf8"), size.audience)},
        subject: ${bounded(Buffer.from(subject, "utf8"), size.subject)},
        header_b64: ${bounded(Buffer.from(base.header, "ascii"), size.header)},
        payload_b64: ${bounded(Buffer.from(base.payload, "ascii"), size.payload)},
        signature_b64: ${bounded(Buffer.from(base.signature, "ascii"), size.signature)},
    }`;
  const wrap = attribute.wrap;
  const tokenBody = wrap
    ? `${type} {
        ${wrap.field}: ${inner.replace(/\n/g, "\n    ")},
${wrap.extra.map(([name, bytes, capacity]) => `        ${name}: ${bounded(bytes, capacity)},\n`).join("")}    }`
    : inner;
  const path = wrap ? `t.${wrap.field}` : "t";
  const imports = [...new Set([input, type])].sort().join(", ");
  let body = `
/// The valid token: ${tokens.token[0].replace(/^the valid token, /, "")}.
pub fn token() -> ${type} {
    ${tokenBody}
}
`;
  for (const [name, [description, , sub]] of Object.entries(tokens)) {
    if (name === "token") continue;
    const t = signed[name];
    body += `
/// ${description[0].toUpperCase()}${description.slice(1)}.
pub fn ${name}() -> ${type} {
    let mut t = token();
${
  sub === subject
    ? ""
    : `    ${path}.subject = ${bounded(Buffer.from(sub, "utf8"), size.subject)};\n`
}    ${path}.payload_b64 = ${bounded(Buffer.from(t.payload, "ascii"), size.payload)};
    ${path}.signature_b64 = ${bounded(Buffer.from(t.signature, "ascii"), size.signature)};
    t
}
`;
  }
  const unformatted = `//! Generated by scripts/fixtures/generators/oidc.mjs; see fixtures/manifest.json. Do not edit.
//! Synthetic ${profile.provider} ID tokens signed with ${keys.summary}${keys.summarySuffix ?? ""}. None is a provider credential.
use ${adapter.crate}::{${imports}};

/// The verifier time the tokens were made for.
pub global NOW: u64 = ${now};
/// The signed \`iat\` and exclusive \`exp\` of \`token()\` (\`exp - iat\` = ${profile.lifetime} s).
pub global ISSUED_AT: u64 = ${issuedAt};
pub global EXPIRY: u64 = ${expiry};
/// The caller binding that every token except \`other_contract()\` carries
/// as its nonce, and the binding at the second contract.
pub global BINDING: Field = 0x${binding};
pub global OTHER_BINDING: Field = 0x${otherBinding};

${keys.globals}
/// The \`header.payload\` of \`token()\` signed under the other key.
pub fn other_key_signature() -> BoundedVec<u8, ${size.signature}> {
    ${bounded(Buffer.from(otherKeySignature, "ascii"), size.signature)}
}
${body}`;
  const fixture = formatNoir(unformatted);
  const directory = `${project}${values.instance}/`;
  await mkdir(directory + "fixtures", { recursive: true });
  await writeFile(directory + "src/fixture.nr", fixture);
  const manifestPath = directory + "fixtures/manifest.json";
  const inputs = {};
  for (const path of [
    ...keys.inputs,
    "aztec/use-cases/scripts/fixtures/generators/oidc.mjs",
    "aztec/use-cases/scripts/fixtures/generators/x509.py",
  ]) {
    inputs[path] = sha256(await readFile(repository + path));
  }
  const record = {
    schema: "uc-fixture-v1",
    scheme,
    use_case: useCase,
    kind: "synthetic",
    generator: {
      argv: [
        "node",
        "scripts/fixtures/generators/oidc.mjs",
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
      library: keys.library,
    },
    inputs,
    key_provenance: keys.provenance,
    claims,
    notes: [
      "The bindings are the instance's caller bindings observed in TXE; the instance test fails with the values to use when they change.",
      `iat of token() is ${age} s before --now and exp - iat is ${profile.lifetime} s; variants keep the exp and move iat by the offset in their description.`,
      `${keys.otherNote}. The importer checks every token.`,
      "Tampering cases mutate these tokens in src/test.nr.",
    ],
    outputs: { "src/fixture.nr": sha256(fixture) },
  };
  await writeFile(manifestPath, JSON.stringify(record, null, 2) + "\n");
  console.log(`Wrote ${values.instance}/src/fixture.nr for binding ${binding}`);
}

await main();
