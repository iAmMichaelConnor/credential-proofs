// The FranceConnect v2 account fixture: its audience, subject and eidas1
// login (standard profile), production issuer, minimum acr 1.
import es256, { NOW } from "./es256.mjs";

export default ({ action }) =>
  es256({
    provider: "franceconnect_v2",
    contract: "FranceConnectV2Account",
    kid: "repository-synthetic-p256",
    claims: {
      iss: "https://oidc.franceconnect.gouv.fr/api/v2",
      aud: "synthetic-fcplus-client",
      sub: "synthetic-pairwise-service-subject",
      nonce: action,
      iat: NOW - 60,
      auth_time: NOW - 60,
      exp: NOW + 60,
      acr: "eidas1",
      amr: ["fc", "pwd"],
    },
    audience: "synthetic-fcplus-client",
    subject: "synthetic-pairwise-service-subject",
    policy: ["sandbox: false", "minimum_acr: 1"],
    capacities: { audience: 128, subject: 256, segments: [192, 1024, 86] },
  });
