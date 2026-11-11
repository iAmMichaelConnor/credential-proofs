# credential-proofs-inputs

Private package that verifies a supplied credential on the host against
explicit policy, then writes the bounded Noir inputs and witness hints of the
matching verifier in [`../../noir`](../../noir/). Host verification is a
preflight: the circuit re-checks every relation, and a consuming contract must
still pin the key and bind issuer, audience, subject, nonce, time and action.
Configured importers fetch public issuer keys only from the reviewed endpoints
in [`src/provider-config.ts`](src/provider-config.ts), never from a token's
`jku` or `x5u`; they do not run OAuth or search for credentials.

## Usage

From the repository root: `npm ci --ignore-scripts`, `npm run build`, then
`npm run credential-proofs-inputs -w credential-proofs-inputs -- --help` for the
exact options. Modules are importable as `credential-proofs-inputs/<module>`.

| CLI route | Module | Writes inputs for |
| --- | --- | --- |
| `oidc import --provider google\|apple\|telegram\|kakao\|miargentina\|facebook` | [oidc.ts](src/oidc.ts) | standalone OIDC examples |
| `facebook import` | [oidc.ts](src/oidc.ts) | Facebook account `AuthInput` |
| `linkedin import` | [linkedin.ts](src/linkedin.ts) | LinkedIn® example (RSA-4096 bearer token) |
| `entra import --tenant GUID` | [entra.ts](src/entra.ts) | Entra |
| `govbr import` | [govbr.ts](src/govbr.ts) | gov.br (explicit environment and minimum level) |
| `line import` | [line.ts](src/line.ts) | LINE |
| `franceconnect import --platform standard\|plus` | [franceconnect.ts](src/franceconnect.ts) | FranceConnect (optional JWE decryption) |
| `singpass import` | [singpass.ts](src/singpass.ts) | Singpass (optional JWE decryption) |
| `jpki challenge`, `jpki import` | [jpki.ts](src/jpki.ts) | JPKI |
| `aadhaar-secure-qr import` | [aadhaar-secure-qr.ts](src/aadhaar-secure-qr.ts) | Aadhaar Secure QR |
| `zupass import` | [zupass.ts](src/zupass.ts) | Zupass POD entry, holder approval and login |
| `ethereum personal-sign\|siwe\|secret-key` | [ethereum.ts](src/ethereum.ts) | Ethereum (key read only from `AUTH_ETHEREUM_PRIVATE_KEY`) |
| `passkey challenge`, `passkey import` | [passkey.ts](src/passkey.ts) | passkey |
| `scripts/import-university.mjs`, `scripts/import-philsys.mjs` | [university.ts](src/university.ts), [philsys.ts](src/philsys.ts) | University / CILogon, PhilSys legacy QR |
| `scripts/alipay-inputs.mjs`, `scripts/wechatpay-inputs.mjs` | | Alipay, WeChat Pay |
| (module only) | [es256.ts](src/es256.ts), [ed25519.ts](src/ed25519.ts), [reclaim.ts](src/reclaim.ts) | generic ES256, Ed25519 hints, Reclaim |

```sh
npm run credential-proofs-inputs -- oidc import --provider google \
  --token-file /secure/path/id-token.jwt --audience CLIENT_ID \
  --subject EXPECTED_SUB --nonce ACTION_NONCE --now 1900000000 \
  --out /secure/path/oidc-Prover.toml
```

Pass an ID token, never an access token, and take `--now` from a trusted
clock. Outputs are written with mode 0600 and can hold reusable login material
or personal data: keep them out of source control and logs. The capture pages
in [`packages/credential-proofs-capture`](../credential-proofs-capture/)
let a user perform their own login or passkey assertion.

## Tests

`npm test` here, or `npm run test:inputs` from the repository root, builds the
package and the synthetic signers in [`tests/builders`](tests/builders/) (a
private test package with deliberately public keys, never imported by
preparation code). Tests make no network calls and use no personal
credentials. `node ../../scripts/fixtures/material/check-provider-jwks.mjs`
is a separate, explicit network check of the Google, Telegram and Apple JWKS
endpoints.
