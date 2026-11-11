// The LINE account fixture: its channel id, subject and amr
// (scripts/fixtures/generate-line-fixture.py).
import es256, { NOW } from "./es256.mjs";

export default ({ action }) =>
  es256({
    provider: "line",
    contract: "LineAccount",
    kid: "synthetic-line-key",
    claims: {
      iss: "https://access.line.me",
      aud: "1234567890",
      sub: "U0123456789abcdef0123456789abcdef",
      nonce: action,
      iat: NOW - 60,
      exp: NOW + 3600,
      amr: ["lineautologin"],
    },
    audience: "1234567890",
    subject: "U0123456789abcdef0123456789abcdef",
    policy: [],
    capacities: { audience: 32, subject: 256, segments: [192, 1024, 86] },
  });
