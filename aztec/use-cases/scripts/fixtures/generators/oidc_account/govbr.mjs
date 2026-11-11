// The gov.br account fixture: a synthetic gold-level ID token from
// createSyntheticGovbr (packages/credential-proofs-inputs/src/govbr.ts) with the account
// policy (production, minimum level silver), plus a bronze-level token for the
// assurance test.
import { array, bounded, credentials, repository } from "../account.mjs";
import { NOW, otherKey, segments } from "./rs256.mjs";

const AUDIENCE = "synthetic-client.gov.br";
const SUBJECT = "12345678900";

export default async function make({ action }) {
  const { createSyntheticGovbr } = await import(
    `credential-proofs-test-builders/govbr`
  );
  const expected = {
    environment: "production",
    audience: AUDIENCE,
    subject: SUBJECT,
    nonce: action,
    now: NOW,
    minimumLevel: "silver",
  };
  const gold = await createSyntheticGovbr(expected, "gold");
  const bronze = await createSyntheticGovbr(
    { ...expected, minimumLevel: "bronze" },
    "bronze",
  );
  const claims = JSON.parse(
    Buffer.from(gold.token.split(".")[1], "base64url").toString("utf8"),
  );
  const key = gold.document.trusted_key;
  const capacities = [128, 2048, 344];
  return {
    contract: "GovbrAccount",
    summary: `A synthetic gov.br ID token under the public synthetic RS256 test key in\n//! fixtures/data. It is not a gov.br credential.`,
    now: NOW,
    expiry: claims.exp,
    extra: `${otherKey(key)}
/// The same login at assurance level bronze, below the policy's silver.
pub fn bronze_auth() -> AuthInput {
    AuthInput {
        policy: auth().policy,
${segments(bronze.token, capacities)}
    }
}
`,
    auth: `    AuthInput {
        policy: AuthPolicy {
            modulus_limbs: ${array(key.modulus_limbs.map(String), "            ")},
            redc_params_limbs: ${array(key.redc_params_limbs.map(String), "            ")},
            audience: ${bounded(Buffer.from(AUDIENCE), 128, "            ")},
            subject: ${bounded(Buffer.from(SUBJECT), 256, "            ")},
            staging: false,
            minimum_level: 2,
        },
${segments(gold.token, capacities)}
    }`,
    claims,
    library: `${credentials}/src/govbr.ts createSyntheticGovbr (gold and bronze)`,
    inputs: [
      `fixtures/data/synthetic-rs256-private.pem`,
      `fixtures/data/synthetic-rs256-public.pem`,
      `${credentials}/src/govbr.ts`,
    ],
    moduleInputs: [
      "aztec/use-cases/scripts/fixtures/generators/oidc_account/rs256.mjs",
    ],
    keyProvenance: `Public synthetic RS256 test key committed in fixtures/data; not a gov.br key. Anyone can sign with it.`,
  };
}
