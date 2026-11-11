// The Singpass account fixture: the local synthetic token of
// fixtures/material/singpass/local-test (production
// issuer, loa:2, audience and subject of its policy.json) with the action
// as nonce, signed deterministically.
import es256, { NOW } from "./es256.mjs";

export default ({ action }) =>
  es256({
    provider: "singpass",
    contract: "SingpassAccount",
    kid: "local-synthetic-singpass",
    claims: {
      iss: "https://id.singpass.gov.sg/fapi",
      aud: "local-synthetic-singpass-client",
      sub: "local-synthetic-singpass-user",
      nonce: action,
      iat: NOW - 60,
      exp: NOW + 3600,
      sub_type: "user",
      acr: "urn:singpass:authentication:loa:2",
      amr: ["pwd", "future-provider-method"],
      sub_attributes: { name: "SYNTHETIC LOCAL TEST" },
    },
    audience: "local-synthetic-singpass-client",
    subject: "local-synthetic-singpass-user",
    policy: ["environment: 0", "minimum_assurance: 2"],
    capacities: { audience: 128, subject: 256, segments: [256, 1024, 86] },
  });
