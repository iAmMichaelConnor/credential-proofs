> [!WARNING]
> **This code has not been audited.** It is experimental software, provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A bug can leave a circuit under-constrained, so that invalid proofs are accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

> [!NOTE]
> This is an independent project. It is not affiliated with, sponsored by or endorsed by any identity provider, government, payment platform or other project named here. Names and logos belong to their owners and are used only to say what this software works with.

# credential-proofs

**Prove who you are, or what you hold, inside a Noir circuit, without handing
over the credential.** Verifiers for the credentials people already have, usable
from any Noir program or Aztec contract.

For example, you can:

- Prove you control a passkey (Face ID, Touch ID, a security key).
- Prove you control an Ethereum address, by a signed message or Sign-In with
  Ethereum.
- Prove you signed in with Google, Apple, Facebook, LinkedIn®, Telegram, Kakao®,
  LINE or Microsoft Entra ID.
- Prove you hold a national identity: gov.br, FranceConnect, Mi Argentina,
  Singpass, Japan's My Number card, Aadhaar or PhilSys.
  - See [zkPassport](https://zkpassport.id/) for a more comprehensive proof-of-passport product (and also proof of other government-issued ids).
- Prove you belong to a university.
- Prove you are a unique human, with World ID.
- Prove you received an email from a particular domain (DKIM).
- Prove a payment was made, with Alipay, WeChat Pay or Peer evidence.
- Prove an attribute from a signed attestation: a Zupass POD or a Reclaim claim.
- Prove a certificate chains to a trusted root and has not been revoked.
- Prove a document was signed with RSA, P-256 or Ed25519.

Each package proves a relation over a credential; the consuming circuit or
contract supplies the trust policy (issuer key, audience, clock, action binding,
replay). Host packages prepare the circuit inputs, and Aztec contracts show the
verifiers in use: World ID gates and a set of use-case contracts (account
authorisation, login links, attribute gates, payment settlement, event proofs).

## What is in the repository

Each package states its API, caller obligations and accepted input profile at
the top of its `src/lib.nr`; the OIDC provider packages share the claim profile
and obligations of [`oidc`](noir/oidc/src/lib.nr). "Known-answer test" is the
end-to-end test of the complete relation in that package (or its
`*_slow_tests` sibling), on the fixture material in [`fixtures/`](fixtures):
*synthetic* means a credential minted under a public test key in the provider's
format and checked against the provider's published key format, *upstream* a
public sample published by the provider or a reference implementation. A
synthetic success shows the relation, not interoperability with the live
provider.

| Credential | Package | Proves | Known-answer test |
| --- | --- | --- | --- |
| Passkey (WebAuthn) | [`passkey_auth`](noir/passkey_auth) | P-256 assertion over a challenge, RP ID, origin and flags | synthetic and upstream (Oxide) |
| Ethereum personal-sign, SIWE, secret key | [`ethereum_auth`](noir/ethereum_auth) | EIP-191 signature, SIWE message, or knowledge of the key of an address | synthetic |
| Google, Apple, generic RS256/ES256 JWT | [`oidc`](noir/oidc) | ID token with bounded JSON claims, exact issuer, audience, subject, nonce and time | synthetic |
| Facebook Limited Login | [`facebook`](noir/facebook) | RS256 ID token with action nonce | synthetic |
| LinkedIn® | [`linkedin`](noir/linkedin) | RS256-4096 bearer ID token (no nonce) | synthetic |
| Telegram Login | [`telegram`](noir/telegram) | RS256 ID token for a bot client | synthetic |
| Kakao® | [`kakao`](noir/kakao) | RS256 ID token for an application | synthetic |
| LINE | [`line`](noir/line) | ES256 ID token for a channel, with `amr` | synthetic |
| Microsoft Entra ID | [`entra`](noir/entra) | Tenant-specific workforce v2 ID token | synthetic |
| gov.br | [`govbr`](noir/govbr) | RS256 ID token with a signed minimum assurance | synthetic |
| FranceConnect, FranceConnect+ | [`franceconnect`](noir/franceconnect) | ES256 token with a signed eIDAS minimum | synthetic |
| Mi Argentina | [`miargentina`](noir/miargentina) | Direct-login RS256 ID token | synthetic |
| Singpass | [`singpass_auth`](noir/singpass_auth) | ES256 FAPI ID token with a signed minimum assurance | synthetic |
| University, CILogon | [`university_auth`](noir/university_auth) | Campus or CILogon-brokered ID token with the signed institutional IdP | synthetic |
| JPKI (My Number card) | [`jpki_auth`](noir/jpki_auth) | Card-holder signature, certificate chain and signed OCSP status | synthetic chain under a test root |
| Zupass POD | [`zupass`](noir/zupass) | POD issuer signature, entry membership, holder approval or login | synthetic (`@pcd/pod`) |
| <img src="docs/assets/reclaim.png" width="20" alt=""> Reclaim | [`reclaim_auth`](noir/reclaim_auth) | Attestor EIP-191 signature over a claim envelope | synthetic |
| Peer V4 | [`peer_v4_auth`](noir/peer_v4_auth) | EIP-712 payment attestation for a pinned intent | synthetic |
| Alipay | [`alipay`](noir/alipay) | Signed v2/v3 response bytes and flat trade claims | synthetic and upstream |
| WeChat Pay | [`wechatpay`](noir/wechatpay) | Signed v3 payment response facts | synthetic |
| Aadhaar Secure QR | [`aadhaar_secure_qr`](noir/aadhaar_secure_qr) | RSA-2048 signature of a UIDAI Secure QR and its fields, demographic nullifier | synthetic and upstream |
| Anon Aadhaar v2 | [`anon_aadhaar_v2_auth`](noir/anon_aadhaar_v2_auth) | Fixed-key Groth16 proof of the Anon Aadhaar v2 circuit, with its policy | upstream proof |
| PhilSys (legacy PhilID QR) | [`philsys_auth`](noir/philsys_auth) | Ed25519 issuer signature on a legacy PhilID QR | synthetic |
| <picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/zkemail-light.svg"><img src="docs/assets/zkemail-dark.svg" width="80" alt=""></picture> zkEmail (DKIM) | [`zkemail`](noir/zkemail) | DKIM signed-header, body-hash and mailbox helpers | upstream mail |
| World ID 3 and 4 | [`world_id_uniqueness`](noir/world_id_uniqueness), [`world_id_common`](noir/world_id_common) | Semaphore or OPRF-nullifier Groth16 proof, root, signal and nullifier policy | synthetic proofs under the real verification keys |
| RSA PKCS#1 v1.5 | [`rsa_signature`](noir/rsa_signature), [`rsa_http`](noir/rsa_http) | RSA-1024/2048/4096 over exact bytes or a digest; an HTTP response envelope | synthetic |
| X.509 and OCSP | [`x509_auth`](noir/x509_auth) | Bounded DER, RSA certificate purpose, OCSP primitives | synthetic |
| P-256 ECDSA | [`p256_auth`](noir/p256_auth) | Signature over a caller-constrained digest, either `s` form | synthetic |
| Ed25519 | [`ed25519_auth`](noir/ed25519_auth) | Strict prime-subgroup Ed25519 | RFC 8032 vectors and edge cases |
| Utilities | [`base64url`](noir/base64url), [`canonical_bytes`](noir/canonical_bytes), [`auth_time`](noir/auth_time) | Canonical base64url decoding, zero-padded byte strings, RFC 3339 UTC to Unix time | unit tests |

Credentials differ in who holds authority and what an action binding means.

| Profile | Holder possession | Action binding | Authority | Replay scope |
| --- | --- | --- | --- | --- |
| Passkey | Registered P-256 credential key | Challenge chosen by the consumer, which computes and displays the action | Holder key; RP ID and origin policy | Consume each challenge once |
| Ethereum personal-sign, SIWE | secp256k1 key of the address | Signed message; SIWE is readable and expires, a raw digest is blind | Holder key | SIWE nonce, or a domain-tagged digest with an enforced deadline |
| Ethereum secret key | Knowledge of the scalar | None | Holder key | Fixed effect only |
| Google, Apple, Telegram, Kakao®, Mi Argentina | The ID token (private witness) | `nonce`, chosen by the enrolled client | Issuer and enrolled client operator | Nonce or token nullifier, before `exp` |
| Facebook | Limited Login ID token | `nonce` = action nonce passed as `LoginConfiguration.nonce` | Issuer and enrolled Limited Login client | As above; generic OAuth access tokens are not accepted |
| LinkedIn® | Bearer ID token, usable by anyone who obtains it | None (no nonce) | Issuer, the relying party that received the token, any holder | Until `exp`; bearer or fixed-effect use only |
| Entra | Tenant ID token | `nonce` | Configured tenant and client operator; the subject may be a guest | Nonce or token nullifier |
| LINE | ES256 ID token (HS256 unsupported) | `nonce`, only where the client can set it | Configured channel and issuer | Nonce or token nullifier |
| gov.br | ID token with signed assurance | `nonce` | Explicit production/staging issuer, client and minimum assurance | Nonce or token nullifier |
| FranceConnect, FranceConnect+ | Inner JWS with signed eIDAS level | `nonce` | Explicit platform policy; the two assurances are not interchangeable | Nonce or token nullifier |
| Singpass | Inner JWS, no delegated actor | `nonce` | Explicit environment, enrolled key and minimum assurance | Nonce or token nullifier |
| University, CILogon | Campus or brokered ID token | `nonce` | Configured issuer; in brokered mode CILogon's statement of the campus IdP. Affiliation is as asserted, not current enrolment | Nonce or token nullifier |
| JPKI | Card authentication key (certified holder) | `challenge(account, action, session)` signed by the holder | Pinned JPKI root and the OCSP responder | Consume the session; OCSP and certificate validity bound expiry |
| Zupass POD | Issuer POD alone: bearer. Holder approval or login: the certified holder key | Holder-signed approval POD (account, action, expiry) or login POD (challenge, issue time) | Issuer for attributes; holder key for actions | Approval expiry or login `max_age`; consumer nullifier |
| Reclaim | Attestor-signed claim | Canonical context built by the app (account, session, action) | Enrolled attestor and approved extraction policy; not website-issued | Session ID or claim identifier as nullifier |
| Alipay | Signed API response (payment evidence) | None by the user; `out_trade_no` is the merchant's | Platform key; it does not identify a merchant | Order reference, consumed by settlement |
| WeChat Pay | Signed payment response (payment evidence) | `attach`, chosen by the merchant | Platform key and merchant | Order reference, consumed by settlement |
| Peer V4 | Attestor-signed payment (payment evidence) | The Peer intent, pinned by the consumer | Peer attestor; Base intent ownership authenticated separately | Peer payment nullifier `keccak256(method \|\| paymentId)` |
| Anon Aadhaar | A copy of the QR | `signal`, chosen by the prover (submitter binding, not holder approval) | Issuer key and the fixed verification key | Credential nullifier once per seed scope |
| Aadhaar Secure QR | A fresh copy of the QR | None; bound to the calling function structurally | Pinned issuer key | Demographic nullifier per app seed |
| PhilSys legacy QR | A copy of the QR | None | Authenticated issuer key; no status or modern COSE support | Consumer-enrolled credential digest |
| zkEmail | A signed mail; a signed `To` does not show control of the address | Body and headers, chosen by the sender | Mail domain key for the selector and period, and the sender or service | No freshness: consumer tracks message identifiers or binds a challenge |
| World ID 3, 4 | World ID secret (proof made on the user's device) | Signal over (chain, version, gate, action, beneficiary, nonce); whoever builds the request chooses the beneficiary | Authenticated root, verification key, issuer/OPRF keys and action | One claim per identity (v3) or account (v4) per action per gate contract |

Only a holder signature, a certified-holder signature or an explicitly trusted
action-bearing issuer or attestor statement can authorise an arbitrary action;
the rest need a fixed effect. The shared primitives (`oidc`, `x509_auth`,
`rsa_signature`, `rsa_http`, `p256_auth`, `ed25519_auth` and the utilities)
authenticate no application account on their own. Direct Twitter/X credentials
are not supported: the generic Reclaim verifier is not an X credential.

### Host packages and Aztec examples

Circuit inputs are prepared on the host by [`packages/credential-proofs-inputs`](packages/credential-proofs-inputs)
(`credential-proofs-inputs`: verifies a supplied credential and encodes the
bounded inputs and hints), [`packages/credential-proofs-world-id`](packages/credential-proofs-world-id)
(`credential-proofs-world-id`: World ID requests, policy and Groth16 codecs) and the
capture pages in [`packages/credential-proofs-capture`](packages/credential-proofs-capture),
where users perform their own login or assertion.

[`aztec/`](aztec) is an Aztec 6.0.0 workspace of example contracts. They are
type-checked and their logic is tested in TXE: by default only the small
keyless shell contract `uc_terms_shell` is compiled and deployed, and a handful
of opt-in deploy tests deploy test-only unconstrained builds of the World ID
gates and of one account ([CONTRIBUTING](CONTRIBUTING.md#example-contracts)).

- [`world-id-v3`](aztec/world-id-v3) and [`world-id-v4`](aztec/world-id-v4):
  `WorldId3Gate` and `WorldId4Gate` verify a World ID proof under a pinned
  verification key, root and action, bind it to
  `[chain, version, gate, action, beneficiary, nonce]` and consume the action
  nullifier. The [World ID guide](docs/world-id.md) covers the policies.
- [`use-cases`](aztec/use-cases/README.md): generic cores (`uc_*`), per-scheme
  adapters and generated instance contracts for account authorisation, login
  links, attribute gating, uniqueness, payment settlement and event proofs.

## Compatibility

The Noir packages are tested with Noir 1.0.0-rc.3, the minimum supported
version (what Aztec 6.0.0 ships), and with Noir 1.0.0, the latest release, on
every pull request, and with Noir nightly every night. Keep this in sync with
the `toolchain` matrix in `.github/workflows/test.yml`.

- `anon_aadhaar_v2_auth` and `world_id_uniqueness` depend on
  [groth16-verifier](https://github.com/iAmMichaelConnor/groth16-verifier)
  v0.1.0 (`groth16`, `runtime_verifier`). Every Groth16 verification here uses
  its stock route (`groth16::verify`, `runtime_verifier::verify`), which runs on
  stock bb.
- `ethereum_auth`, `anon_aadhaar_v2_auth`, `peer_v4_auth`, `reclaim_auth` and
  `world_id_common` depend on [noir-lang/keccak256](https://github.com/noir-lang/keccak256)
  at `tag = "main"`, tested at commit `7b1894dd57c0c3d137ebc8d7d597151e372930c4`.
- `zupass` depends on [noir-lang/noir-edwards](https://github.com/noir-lang/noir-edwards)
  at `tag = "main"`, tested at commit `31e43df83a38c2e17474f7e0fa4762daca3fde92`,
  which contains noir-edwards #55 (no tagged release does).
- `rsa_signature` depends on [iAmMichaelConnor/noir_rsa](https://github.com/iAmMichaelConnor/noir_rsa)
  at `tag = "v0.12.1-assert-messages.1"`: zkpassport/noir_rsa v0.12.1 plus the
  assert messages proposed in zkpassport/noir_rsa#22 to #24.
- Other dependencies are tagged releases: noir-bignum, noir_bigcurve,
  sha256, sha512, sha1, poseidon, noir_base64, noir-edwards-bignum and zk-kit
  `binary-merkle-root`; `vendor/noir-ed25519` is a modified copy of
  willemolding/noir-ed25519 (see [NOTICE](NOTICE)).
- The [Aztec examples](aztec) are tested with Aztec 6.0.0 only: Aztec.nr
  `v6.0.0`, nargo 1.0.0-rc.3 and bb 6.0.0. Keep this in sync with
  `AZTEC_VERSION` in `.github/workflows/test.yml` and with
  [`aztec/.aztecrc`](aztec/.aztecrc).

### Known issues

- groth16-verifier v0.1.0 is not published yet; until it is, a contributor
  provides it locally ([CONTRIBUTING](CONTRIBUTING.md#setup)).

## Installation

In your `Nargo.toml`, add the packages you use. Each lives in its own directory
of this repository:

```toml
[dependencies]
oidc = { git = "https://github.com/iAmMichaelConnor/credential-proofs", tag = "v0.1.0", directory = "noir/oidc" }
passkey_auth = { git = "https://github.com/iAmMichaelConnor/credential-proofs", tag = "v0.1.0", directory = "noir/passkey_auth" }
```

Use one tag for every package from this repository, so that shared types (the
OIDC token and key types, the RSA key) have one identity.

## Usage

A Google ID token under a key, audience, subject, nonce and clock that the
caller trusts (enrolled policy, never the token):

```rust
use oidc::{JwtInput, TrustedRsaKey};

fn google_login(
    token: JwtInput<128, 1024, 344>,
    trusted_key: TrustedRsaKey,
    audience: BoundedVec<u8, 128>,
    subject: BoundedVec<u8, 64>,
    nonce: BoundedVec<u8, 64>,
    now: u64,
) {
    let _claims = oidc::verify_google(token, audience, subject, nonce, now, trusted_key);
}
```

A WebAuthn assertion over a challenge the consumer computed from the action:

```rust
use passkey_auth::webauthn::{assert_valid_webauthn, PasskeyPublicKey, WebAuthnAssertion, WebAuthnPolicy};

fn approve(
    public_key: PasskeyPublicKey,
    challenge: Field,
    policy: WebAuthnPolicy<64, 128>,
    assertion: WebAuthnAssertion<256>,
) {
    assert_valid_webauthn::<256, 64, 128>(public_key, challenge, policy, assertion);
}
```

The building blocks have direct entry points:

```rust
let decoded = base64url::decode_canonical(encoded, "token payload");              // canonical unpadded base64url
p256_auth::verify_p256_digest(key, signature, digest);                            // P-256 ECDSA over a constrained digest
rsa_signature::RSAPubkey::new(modulus, redc).verify_rsa_sha256_pkcs1v15(body, signature);
ed25519_auth::verify(key, signature, message, key_hint, signature_hint);          // strict Ed25519
let claims = token.verify_es256(oidc::literal_vec("https://issuer.example"), audience, subject, nonce, now, key);
```

Every known-answer test calls the package's benchmark function, which is the
complete relation with the shapes used in the tests (for example
[`oidc/src/benchmarks.nr`](noir/oidc/src/benchmarks.nr)); read it for the
input shapes of each credential.

## Benchmarks

Circuit size (`bb gates` `circuit_size`) of the `#[export]` benchmark
functions, each a complete relation with its known-answer shapes, measured with
Noir 1.0.0 and bb 6.0.0 on 2026-11-10. Each count is the whole function,
including its ABI and the backend's fixed per-circuit cost. The
[benchmark workflow](.github/workflows/benchmark.yml) reports current numbers on
pull requests and, when started by hand, records history on the `gh-pages`
branch.

| Relation | Benchmark | Circuit size |
| --- | --- | ---: |
| Canonical base64url decode, 344-byte input | `base64url_decode_344` | 8,173 |
| Zupass POD signature and entry | `zupass_pod_entry` | 19,821 |
| P-256 ECDSA over a digest | `p256_black_box_verify` | 45,999 |
| Alipay v2 RSA2 response (512 bytes) | `alipay_v2_response` | 65,219 |
| zkEmail RSA-2048 signature | `zkemail_rsa_signature_compat` | 91,090 |
| WebAuthn passkey assertion | `passkey_webauthn` | 99,032 |
| Ethereum EIP-191 personal-sign | `ethereum_personal_sign` | 125,398 |
| Aadhaar Secure QR, RSA-2048 and fields | `aadhaar_secure_qr_verify` | 150,722 |
| Sign-In with Ethereum | `ethereum_siwe` | 203,664 |
| Peer V4 payment attestation | `peer_v4_verify` | 237,357 |
| Generic ES256 JWT | `oidc_es256_jwt` | 250,248 |
| Reclaim attestor envelope | `reclaim_verify_claim` | 311,203 |
| Alipay v3 response and user identity (512 bytes) | `alipay_v3_response` | 367,847 |
| Strict Ed25519, 18-byte message | `ed25519_verify_18` | 404,863 |
| Ethereum secret-key knowledge | `ethereum_secret_key` | 425,612 |
| Anon Aadhaar v2 Groth16 and policy | `anon_aadhaar_v2_verify` | 429,483 |
| World ID Groth16, 4 public inputs (runtime key) | `world_id_groth16_producer_4` | 597,827 |
| PhilSys legacy QR | `philsys_verify` | 683,304 |
| Kakao® ID token (RS256) | `kakao_verify` | 1,021,899 |
| Apple ID token (RS256) | `oidc_apple` | 1,021,913 |
| Telegram Login ID token (RS256) | `telegram_verify` | 1,021,920 |
| Mi Argentina ID token (RS256) | `miargentina_verify` | 1,021,927 |
| Google ID token (RS256) | `oidc_google` | 1,022,041 |
| Facebook Limited Login (RS256) | `facebook_verify` | 1,023,683 |
| World ID Groth16, 15 public inputs (runtime key) | `world_id_groth16_producer_15` | 1,179,258 |
| WeChat Pay v3 response (1,024 bytes) | `wechatpay_v3_response` | 1,192,379 |
| LINE ID token (ES256) | `line_verify` | 1,268,417 |
| FranceConnect+ (ES256) | `franceconnect_v1_verify` | 1,420,929 |
| FranceConnect v2 (ES256) | `franceconnect_v2_verify` | 1,420,929 |
| Entra tenant ID token (RS256) | `entra_verify` | 1,974,966 |
| gov.br ID token (RS256) | `govbr_verify` | 2,188,583 |
| Singpass ID token (ES256) | `singpass_authorise` | 2,339,019 |
| LinkedIn® bearer ID token (RS256-4096) | `linkedin_verify_bearer` | 3,366,758 |
| JPKI card, certificate and OCSP | `jpki_authorise` | 3,931,447 |
| University or CILogon ID token | `university_verify_login` | 4,004,191 |

To generate the reports locally (`--jobs` exports and measures that many
packages at once; the largest exports need about 7 GB each):

```bash
BACKEND=bb ./scripts/build-gates-report.sh --jobs 2
```

## Security

If you find a vulnerability, please **do not** open a public issue. Report it
privately via [GitHub's "Report a vulnerability"](https://github.com/iAmMichaelConnor/credential-proofs/security/advisories/new)
form instead.

- **Bind meaning.** A verifier proves a relation over a credential. The
  consumer chooses which keys, issuers and claims authorise which action, binds
  the action, and prevents replay. Read [docs/SECURITY.md](docs/SECURITY.md)
  before composing a verifier into an application.
- **Keys come from policy.** An issuer key taken from the evidence proves
  nothing. RSA Barrett limbs are a hint: identify a key by its modulus alone.
- **Fixtures are synthetic.** The known-answer tests establish the relation on
  test material, not interoperability with a live provider.
- **Backend premises.** Some relations rely on properties of bb 6.0.0 (memory
  index bounds in [Zupass](docs/zupass.md#backend-and-compiler-premises); see
  also the black-box notes in [`p256_auth`](noir/p256_auth/src/lib.nr)).
  Recheck them before moving to another backend.

Deeper material: [security and composition](docs/SECURITY.md),
[World ID](docs/world-id.md), [Zupass](docs/zupass.md) and
[zkEmail](docs/zkemail.md).

## Trademarks

This project is independent. It is not affiliated with, sponsored by or endorsed
by any provider, government or platform named in it, and it is not an approved
integration of any of them. Their names are used only to say which credential
formats the verifiers accept. Most verifiers are tested on synthetic credentials
in the provider's format (see the table above), not against the live service.

- Apple is a trademark of Apple Inc., registered in the U.S. and other countries
  and regions.
- Google is a trademark of Google LLC.
- Facebook is a trademark of Meta Platforms, Inc.
- Kakao® is a trademark of Kakao Corp.
- LINE is a trademark or registered trademark of LY Corporation.
- LinkedIn® is the registered trademark of LinkedIn Corporation or its
  affiliates. The use of the LinkedIn® trademark in connection with this product
  does not signify any affiliation with or endorsement by LinkedIn Corporation or
  its affiliates.
- Microsoft and Microsoft Entra are trademarks of the Microsoft group of
  companies.

All other names, including those of government identity schemes, payment
platforms and open-source projects, belong to their respective owners. The
zkEmail and Reclaim logos are shown under the terms recorded in
[docs/assets](docs/assets/README.md).

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
