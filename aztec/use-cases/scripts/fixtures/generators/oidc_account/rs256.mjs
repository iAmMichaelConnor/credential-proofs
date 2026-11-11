// RS256 tokens from createSyntheticOidc (packages/credential-proofs-inputs/src/oidc.ts)
// for the accounts whose policy is (modulus, Barrett parameters, audience,
// subject) and whose input is the three base64url segments.
import {
  array,
  bounded,
  credentials,
  padded,
  repository,
} from "../account.mjs";

export const NOW = 1900000000;

const join = (parts) =>
  parts.reduceRight((acc, limb) => (acc << 120n) + BigInt(limb), 0n);
const split = (value) =>
  Array.from({ length: 18 }, (_, i) =>
    ((value >> (120n * BigInt(i))) & ((1n << 120n) - 1n)).toString(),
  );

/// Another well-formed 2048-bit modulus (n + 2) and its Barrett parameters,
/// for a wrong-key test that reaches the signature check.
export function otherKey(trusted) {
  const modulus = join(trusted.modulus_limbs) + 2n;
  return `/// Another well-formed 2048-bit RSA modulus (the key's modulus + 2) and its
/// Barrett parameters. No token is signed under it.
pub global OTHER_MODULUS_LIMBS: [u128; 18] = ${array(split(modulus), "")};
pub global OTHER_REDC_PARAMS_LIMBS: [u128; 18] = ${array(split((1n << 4102n) / modulus), "")};
`;
}

/// The input segments as `name: [..], name_len: n,` lines.
export function segments(token, capacities) {
  return ["header_b64", "payload_b64", "signature_b64"]
    .map((name, i) => {
      const bytes = Buffer.from(token.split(".")[i], "ascii");
      return `        ${name}: ${padded(bytes, capacities[i], "        ")},\n        ${name}_len: ${bytes.length},`;
    })
    .join("\n");
}

export default function rs256(
  provider,
  contract,
  audience,
  subject,
  capacities = [128, 1024, 344],
) {
  return async ({ action }) => {
    const { createSyntheticOidc } = await import(
      `credential-proofs-test-builders/oidc`
    );
    const { token, document } = await createSyntheticOidc(provider, {
      audience,
      subject,
      nonce: action,
      now: NOW,
    });
    const claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
    const key = document.trusted_key;
    return {
      contract,
      summary: `A synthetic ${provider} ID token under the public synthetic RS256 test key in\n//! fixtures/data. It is not a provider credential.`,
      now: NOW,
      expiry: claims.exp,
      extra: otherKey(key),
      auth: `    AuthInput {
        policy: AuthPolicy {
            modulus_limbs: ${array(key.modulus_limbs.map(String), "            ")},
            redc_params_limbs: ${array(key.redc_params_limbs.map(String), "            ")},
            audience: ${bounded(Buffer.from(audience), 128, "            ")},
            subject: ${bounded(Buffer.from(subject), 256, "            ")},
        },
${segments(token, capacities)}
    }`,
      claims,
      library: `${credentials}/src/oidc.ts createSyntheticOidc("${provider}")`,
      inputs: [
        `fixtures/data/synthetic-rs256-private.pem`,
        `fixtures/data/synthetic-rs256-public.pem`,
        `${credentials}/src/oidc.ts`,
      ],
      moduleInputs: [
        "aztec/use-cases/scripts/fixtures/generators/oidc_account/rs256.mjs",
      ],
      keyProvenance: `Public synthetic RS256 test key committed in fixtures/data; not a ${provider} key. Anyone can sign with it.`,
    };
  };
}
