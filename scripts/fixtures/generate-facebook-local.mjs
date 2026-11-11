#!/usr/bin/env node
import { createSyntheticOidc } from "credential-proofs-test-builders/oidc";

import { writeToml } from "credential-proofs-inputs/toml";


const output =
  process.argv[2] ??
  new URL("../../target/kat/facebook/Prover.toml", import.meta.url);
const expected = {
  audience: "synthetic-facebook-app-id",
  subject: "synthetic-pairwise-subject",
  nonce: "d57f3d0a1ea15b8812e50be497737f59b83ef0f1b30621c333086c48227bd22f",
  now: 1_900_000_000,
};
const fixture = await createSyntheticOidc("facebook", expected);
// The benchmark takes the Google-shaped layout: private token segments and a
// public trusted key, audience, subject, nonce and time.
await writeToml(output, fixture.document);
console.log(
  `wrote a synthetic Facebook-shape local verifier fixture to ${output}; it is not provider-issued`,
);
