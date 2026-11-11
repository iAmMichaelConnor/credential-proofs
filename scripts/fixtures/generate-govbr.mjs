// Synthetic fixtures use the repository's public RSA test PEM, never issuer keys.
import { writeFile } from "node:fs/promises";
import { createSyntheticGovbr } from "credential-proofs-test-builders/govbr";

import { stringifyToml } from "credential-proofs-inputs/toml";

const x = await createSyntheticGovbr({
  environment: "production",
  audience: "synthetic-client.gov.br",
  subject: "12345678900",
  nonce: "0".repeat(64),
  now: 1900000000,
  minimumLevel: "silver",
});
await writeFile(
  new URL("../../target/kat/govbr/Prover.toml", import.meta.url),
  stringifyToml(x.document),
);
await writeFile(
  new URL("../../fixtures/data/generated/govbr.synthetic.json", import.meta.url),
  JSON.stringify(x, null, 2) + "\n",
);
