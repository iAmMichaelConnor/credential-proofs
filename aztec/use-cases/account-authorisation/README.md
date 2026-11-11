> **Experimental software. Unaudited. May contain bugs.**

# Account authorisation (U1)

Statement: "the account owner approved this exact payload". The credential
authorises an arbitrary transaction, so only evidence of categories 1 to 4 is
admissible: the user's own key, a certified user key, an identity provider
that signed a value carrying the action (an OIDC nonce that the client chose,
or a mail body that the sender wrote), or an attestor that signed a context
that the prover chose. Payment events, static documents and bearer tokens
cannot carry the action, and a separately enrolled key never makes them
admissible ([ARCHITECTURE.md](../ARCHITECTURE.md#trust-carried-by-every-claim)).

Core crate: [`uc_account`](common/src/lib.nr) (`AccountAuthorisation`,
`AccountGrant`, `entrypoint`, the trust constructors for adapters). Each
instance keeps its policy, credential input and trait implementation in its
own contract crate, because the account address commits to the artifact.

## Rules

1. The account address commits to its policy:
   `immutables_hash = Poseidon2([SCHEME, Poseidon2(policy.serialize())])`.
2. `check_input` runs the checks that need no action hash (the Reclaim
   account checks its username and session id here).
3. `action = Poseidon2([MIKE_AUTH_ENTRYPOINT_V1, SCHEME, this_address,
   chain_id, version, payload.hash()])`. The payload hash includes `tx_nonce`.
4. The adapter verifies the credential over `action` and returns a grant.
5. Admissibility: `trust.source` is 1 to 4; `also_authorised` has no copy
   holder; `binding.set_by` is holder, OIDC client, mail sender or prover;
   `binding.value == action`. The check reads the adapter's labels: an
   adapter that bolts an enrolled key onto a credential and reports
   `SOURCE_USER_KEY` passes it, so the no-bolt-on rule is a review rule.
6. The grant's session nullifier, if any, is pushed (the adapter
   domain-separates it).
7. The grant's expiration timestamp, if any, limits inclusion. The core does
   not compare it with the anchor block, so an adapter that needs a
   pre-execution expiry check makes it itself; otherwise an expired
   credential is rejected no later than inclusion.
8. The account-siloed nullifier of `tx_nonce` is pushed and the payload's
   calls execute. A replayed payload fails on that nullifier.

`SCHEME` names the provider and its credential, enters the policy commitment
and the action hash, and differs per account; an id stays fixed when an
instance is removed.

## Residual risks

- No admissible credential shows the user the payload. The software that
  requests a credential must compute the action from the payload itself and
  show the payload; any page that can request a credential for the enrolled
  key, client or mailbox can obtain one for any action. The instance table
  says what each credential displays instead.
- OIDC accounts: the client chooses the nonce, and single sign-on can skip
  the consent screen, so the protection is the user's trust in that client.
  The provider and the client operator can authorise any action.
- zkEmail requires a service-controlled sender mailbox: the service is the
  authority. Reclaim: the attestor is part of the authority and the prover
  writes the context.
- Credentials without an expiry (passkey, secret key, zkEmail) rely on the
  transaction nonce alone: an unused approval stays valid until its nonce
  is consumed.
- Holder approval PODs (zupass) and raw holder signatures: never sign, for
  another party, a POD with `_aztec_auth_v1_*` entries or a raw field
  (`signPODRoot`, `signMessage`, Semaphore `Identity.signMessage`). See the
  [Zupass notes](../../../docs/zupass.md#holder-key-hazards)
  and `signHolderApproval` in
  [zupass.ts](../../../packages/credential-proofs-inputs/src/zupass.ts).

The OIDC accounts (apple, entra, facebook, franceconnect, franceconnect_v2,
google, govbr, kakao, line, miargentina, telegram) prove that the key that
the policy pins signed an ID token of the provider's issuer for the pinned
client id and subject, whose `nonce` is the lowercase hex of the action and
whose `exp` is after the anchor block (`nbf`, if present, not after it); the
account requests inclusion strictly before `exp`. Their in-crate input
implements `uc_family_oidc::OidcProviderInput`, wrapped in `OidcAccount`.
The verifier does not fetch the provider's key set, so a key rotation needs
a new account.

## Preparing account inputs

No host code in this repository computes an account's `immutables_hash` or
encodes its `AuthPolicy`. Poseidon2 is Aztec's `poseidon2_hash`
(`poseidon2Hash` in `@aztec-labs/foundation`) over the contract's own
`Serialize` layout: one field per scalar, arrays element by element and a
`BoundedVec` as its storage followed by its length, in struct field order.
The credentials CLI ([`packages/credential-proofs-inputs`](../../../packages/credential-proofs-inputs))
writes inputs in the library packages' own layout (top-level fields, smaller
capacities); only `facebook import` writes an
account `AuthInput`. An account deployed with a hash computed from another
layout rejects every call ("Wrong account policy"), and assets sent to its
address cannot move. Compute the hash with the account's own Noir types, as
`uc_account::txe::deploy` does.

## Tests

`common/src/tests.nr` covers admissibility, the literal values and the SIWE
calendar. `../testing/core_tests/src/account.nr` (TXE) covers a valid grant,
payload replay, a wrong action, a new nonce, session replay, the input
check, the expiry passed to the transaction, and payment and bearer evidence,
through both `entrypoint_with_bound_policy` and the public `entrypoint` at a
`uc_terms_shell` instance (plus a wrong policy and an expired credential), so
the mirrored cases catch drift between the two bodies.

Each instance's `src/test.nr` runs `uc_account::entrypoint` at the keyless
shell with the instance's fixture, also at a second account with the same
policy, and submits the same payload twice (`replay_rejected`).
`fixture_action_is_the_action` (or `fixture_is_for_this_account` in
`mod release`) prints the action to regenerate the fixture with. TXE fixes
the chain id and version, so no test changes them; the action binds both.
No test compiles or deploys an account contract, so the calls of a payload
do not run: TXE refuses contract calls inside a private context. The
secret-key account's `authorised_private_call_is_dispatched` shows that the
entrypoint reaches a payload's private call.

## Instances

<!-- use-case-instances:start -->
Each instance is a contract in `<scheme>/src/main.nr`, entrypoint `entrypoint(payload, auth)`, package `<scheme>_auth_account` (zkemail: `dkim_auth_account`), tested by `scripts/test-use-cases.sh account-authorisation/<scheme>`. Its `src/test.nr` has the tests `valid`, `replay_rejected`, `wrong_issuer_rejected`, `wrong_action_rejected`, `wrong_policy_rejected`, `expired_rejected`; [use-cases.json](../use-cases.json) records each exception and its reason. The category is the evidence category of [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).

| Instance | Category | Contract | Adapter | Residual risk and notes |
| --- | --- | --- | --- | --- |
| [apple](apple/src/main.nr) | 3 | `AppleAccount` | in-crate input via `OidcAccount` | Only `sub` (per developer team) is pinned; the private relay e-mail and real-user indicator are not checked. |
| [entra](entra/src/main.nr) | 3 | `EntraAccount` | in-crate input via `OidcAccount` | The issuer pins the tenant GUID; the tenant's administrators control its users and sign-in policy and are co-authorities. `sub` is pairwise per application. |
| [ethereum_personal_sign](ethereum_personal_sign/src/main.nr) | 1 | `EthereumSignatureAccount` | in-crate input | Blind signing: the wallet shows 32 opaque bytes, the shape many sites use for login nonces, so a phishing page can present an account action as a login and pick the deadline; prefer ethereum_siwe. An unused approval stays valid until its deadline. |
| [ethereum_secret_key](ethereum_secret_key/src/main.nr) | 1 | `EthereumSecretKeyAccount` | in-crate input | No signature: the secret key is a private input of the transaction proof, so a hardware wallet cannot use this account and anything that sees the prover inputs sees the key. The key authorises any payload at every account that pins its address. |
| [ethereum_siwe](ethereum_siwe/src/main.nr) | 1 | `EthereumSiweAccount` | in-crate input | The wallet shows the domain, URI and expiry, but the action only as a hex nonce. No statement, request id, not-before or resources field; domain and URI are checked as visible ASCII, not parsed as RFC 3986. `Issued At` after the anchor block is rejected: signers set it at or before the anchor block time. |
| [facebook](facebook/src/main.nr) | 3 | `FacebookAccount` | in-crate input via `OidcAccount` | Limited Login proves control of the Facebook account at the app, not civil identity. |
| [franceconnect](franceconnect/src/main.nr) | 3 | `FranceConnectAccount` | in-crate input via `OidcAccount` | FranceConnect+ encrypts the ID token (JWE); the host decrypts it and the circuit verifies the inner signed token. |
| [franceconnect_v2](franceconnect_v2/src/main.nr) | 3 | `FranceConnectV2Account` | in-crate input via `OidcAccount` | A policy with minimum level 1 accepts `eidas1`, a low-assurance login. |
| [google](google/src/main.nr) | 3 | `GoogleAccount` | in-crate input via `OidcAccount` | - |
| [govbr](govbr/src/main.nr) | 3 | `GovbrAccount` | in-crate input via `OidcAccount` | gov.br tokens live 60 s, which bounds the inclusion window. |
| [jpki](jpki/src/main.nr) | 2 | `JpkiAccount` | in-crate input | `anchor_class` 1 accepts any root the policy pins; only class 0 restricts it to the official JPKI roots. The card signs an opaque challenge. The session nullifier is siloed by account, so one card session can serve another account of the same card if the card signs for it. |
| [kakao](kakao/src/main.nr) | 3 | `KakaoAccount` | in-crate input via `OidcAccount` | - |
| [line](line/src/main.nr) | 3 | `LineAccount` | in-crate input via `OidcAccount` | - |
| [miargentina](miargentina/src/main.nr) | 3 | `MiArgentinaAccount` | in-crate input via `OidcAccount` | No RENAPER SID biometric assertion is checked, and the subject semantics are unconfirmed. |
| [passkey](passkey/src/main.nr) | 1 | `PasskeyAccount` | in-crate input | Blind signing: the authenticator shows the RP ID, not the action; a page on the pinned origin can request an assertion over any action. The assertion has no expiry: an unused one stays valid until its transaction nonce is consumed. |
| [singpass](singpass/src/main.nr) | 3 | `SingpassAccount` | in-crate input | Production requires assurance level 2 or more. Singpass encrypts the ID token (JWE); the host decrypts it and the circuit verifies the inner signed token. |
| [telegram](telegram/src/main.nr) | 3 | `TelegramAccount` | in-crate input via `OidcAccount` | - |
| [twitter_reclaim](twitter_reclaim/src/main.nr) | 4 | `TwitterReclaimAccount` | in-crate input | The attestor is a co-authority and the prover writes the context. The official X provider profile rejects every nonempty proof, so this account cannot be used with it; a field named `username` does not establish its provenance. The session nullifier is siloed by account. |
| [university](university/src/main.nr) | 3 | `UniversityAccount` | in-crate input | Does not show current student or staff status: affiliation is not checked. CILogon reports the campus IdP and is a co-authority. |
| [zkemail](zkemail/src/main.nr) | 3 | `DkimAccount` | in-crate input | The service that operates the pinned sender mailbox must send the action mail only at the mailbox owner's request; ownership is not inferred from `To`. The mail has no expiry: only the transaction nonce stops a replay. |
| [zupass](zupass/src/main.nr) | 2 | `ZupassAccount` | in-crate input | The approval POD's action entry is an opaque hash. Software that signs, for another party, a POD with `_aztec_auth_v1_*` entries or a raw field (`signPODRoot`) with the holder key is a signing oracle for this account. The policy pins one `content_id`, so another POD the issuer signs for another key does not count. |
<!-- use-case-instances:end -->
