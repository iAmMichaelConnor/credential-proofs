// The FranceConnect+ account fixture: its audience, subject and eidas2
// login, production issuer, minimum acr 2.
import es256, { NOW } from "./es256.mjs";

export default ({ action }) =>
  es256({
    provider: "franceconnect",
    contract: "FranceConnectAccount",
    kid: "repository-synthetic-p256",
    claims: {
      iss: "https://auth.franceconnect.gouv.fr/api/v2",
      aud: "synthetic-fcplus-client",
      sub: "synthetic-pairwise-service-subject",
      nonce: action,
      iat: NOW - 60,
      auth_time: NOW - 60,
      exp: NOW + 60,
      acr: "eidas2",
      amr: ["fc", "pwd"],
    },
    audience: "synthetic-fcplus-client",
    subject: "synthetic-pairwise-service-subject",
    policy: ["integration: false", "minimum_acr: 2"],
    capacities: { audience: 128, subject: 256, segments: [192, 1024, 86] },
  });
