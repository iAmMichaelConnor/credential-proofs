// ES256 tokens for the P-256 OIDC accounts (LINE, FranceConnect,
// FranceConnect v2, Singpass): JSON claims signed with the repository's
// public synthetic P-256 scalar 42 (packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts,
// deterministic RFC 6979). Their policy pins (public key x, y, audience,
// subject, provider flags) and their input is the three base64url segments.
import {
  array,
  bounded,
  credentials,
  padded,
  repository,
  require,
} from "../account.mjs";

export const NOW = 1900000000;

const point = (scalar) => {
  const { p256 } = require("@noble/curves/p256");
  const secret = Buffer.alloc(32);
  secret[31] = scalar;
  return Buffer.from(p256.getPublicKey(secret, false));
};

/// The policy key (scalar 42) and another key (scalar 43, nothing signed).
export const KEY = point(42);
export const OTHER = point(43);

export function otherKey() {
  return `/// Another P-256 public key (the public test scalar 43). Nothing is signed under it.
pub global OTHER_KEY_X: [u8; 32] = ${array([...OTHER.subarray(1, 33)], "")};
pub global OTHER_KEY_Y: [u8; 32] = ${array([...OTHER.subarray(33, 65)], "")};
`;
}

/// Builds the made-fixture record of oidc_account.mjs. `claims` is signed
/// as JSON; `policy` lists the provider-specific policy lines after the
/// key, audience and subject.
export default async function es256({
  provider,
  contract,
  kid,
  claims,
  audience,
  subject,
  policy,
  capacities,
}) {
  const { signSyntheticEs256 } = await import(
    `credential-proofs-test-builders/synthetic-es256`
  );
  const token = signSyntheticEs256(claims, kid);
  const lines = ["header_b64", "payload_b64", "signature_b64"]
    .map((name, i) => {
      const bytes = Buffer.from(token.split(".")[i], "ascii");
      return `        ${name}: ${padded(bytes, capacities.segments[i], "        ")},\n        ${name}_len: ${bytes.length},`;
    })
    .join("\n");
  return {
    contract,
    summary: `A synthetic ${provider} ID token (ES256) under the public synthetic P-256\n//! test scalar 42 of packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts. It is not a provider credential.`,
    now: NOW,
    expiry: claims.exp,
    extra: otherKey(),
    auth: `    AuthInput {
        policy: AuthPolicy {
            public_key_x: ${array([...KEY.subarray(1, 33)], "            ")},
            public_key_y: ${array([...KEY.subarray(33, 65)], "            ")},
            audience: ${bounded(Buffer.from(audience), capacities.audience, "            ")},
            subject: ${bounded(Buffer.from(subject), capacities.subject, "            ")},
${policy.map((line) => `            ${line},`).join("\n")}
        },
${lines}
    }`,
    claims: {
      header: JSON.parse(
        Buffer.from(token.split(".")[0], "base64url").toString("utf8"),
      ),
      ...claims,
    },
    library: `packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts signSyntheticEs256 (P-256 scalar 42, RFC 6979)`,
    inputs: [`packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts`],
    moduleInputs: [
      "aztec/use-cases/scripts/fixtures/generators/oidc_account/es256.mjs",
    ],
    keyProvenance: `Public synthetic P-256 scalar 42 (packages/credential-proofs-inputs/tests/builders/src/synthetic-es256.ts); not a ${provider} key. Anyone can sign with it.`,
  };
}
