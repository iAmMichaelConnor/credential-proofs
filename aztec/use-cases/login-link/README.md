> **Experimental software. Unaudited. May contain bugs.**

# Login link (U2)

Statement: "whoever controls this external identity just logged in, and the
login was bound to this Aztec caller". Bearer providers (LinkedIn®) are
accepted only when the terms say so, and the claim is labelled bearer: a
bearer login is not bound to the caller, so whoever holds a copy of the
token can link it.

Core crate: [`uc_login_link`](common/src/lib.nr) (`LoginLink`, `LinkClaim`,
`LinkTerms { accepted, max_age, allow_bearer, scope, round }`, `link`). The
instance records the identity through its scoped nullifier and returns it;
the examples keep no identity-to-address registry.

## Rules

1. `challenge = Poseidon2(MIKE_UC_LOGIN_LINK_CHALLENGE_V1, chain_id, version,
   this_address, msg_sender, round)`. The adapter puts it in the credential's
   free field (nonce, body, context).
2. Trust accepted.
3. A login is bearer exactly when its binding was set by no one. A bearer
   login needs `allow_bearer`; any other login must bind the challenge.
4. Freshness: `issued_at` at most `max_age` before the anchor block, and
   inclusion by `issued_at + max_age`; a login labelled `ALSO_COPY_HOLDER`
   gets at most 4 hours. The credential's own exclusive expiry must be after
   the anchor block and also limits inclusion.
5. One link per identity per app: nullifier
   `Poseidon2(MIKE_UC_LOGIN_LINK_V1, scope, identity)`.

OIDC instances use the `uc_family_oidc` wrappers: `OidcLink` puts the
challenge in the nonce; `OidcBearerLink` (LinkedIn®) passes no nonce, labels
the claim bearer and requires `SignedIssueTime`, because the bearer ceiling
is the only limit on how long a copy stays usable. Every OIDC adapter reports
the token's signed `iat`, which must not be after the anchor block. The
anchor block lags wall time, which shortens the usable window of short-lived
tokens (gov.br: 60 s). Each OIDC link returns `subject_id(Poseidon2(issuer),
sub)`; what `sub` means differs per provider (instance table).

A credential that carries no time of its own (passkey, JPKI, Zupass) signs
`timed_challenge(challenge, issued_at)`: the holder states the issue time,
so freshness limits how long a signature stays usable after it was made, not
what the holder can sign. For user keys, `Trust.issuer` pins the relying
party (passkey RP ID and origin, SIWE domain, URI and chain), not a key.
Key-holder schemes bind the link to whoever holds the key; the certificate
issuer adds no co-authority, since a key it holds is another identity.

## Residual risks

- Bearer logins: anyone who holds the token (the relying party, a log, a
  proxy) can link it to their own address until it is stale.
- OIDC: the provider and the client operator can produce a login for any
  challenge, and the consent screen does not show it. zkEmail: the mail
  domain and operator can. Reclaim: the attestor can.
- Key-holder schemes: the page, wallet or card middleware that requests the
  signature chooses the challenge, and no authenticator shows it.
- One link per identity per scope: a user who loses the linked Aztec account
  needs a new scope or round to link again.

## Tests

`common/src/tests.nr` covers the context-free rules. The TXE tests in
`../testing/core_tests/src/login_link.nr` cover a valid link, a second link
of the same identity, a wrong challenge, stale and expired logins, a wrong
issuer, bearer logins refused and accepted, the bearer ceiling, and the
requested inclusion expiry (freshness deadline, a login exactly `max_age`
old, the credential expiry and the bearer ceiling), and `link` with valid and
wrong terms at deployed keyless shells.

ES256 instances name the signature failure. The RS256 digest comparison of
noir_rsa has no assertion message, so RS256 instances use a bare
`should_fail` for `wrong_key_rejected` and `bad_signature_rejected` and show
the cause with positive tests: the other key verifies its own signature over
the fixture token and has a larger modulus, and the substituted signature is
a valid signature of the pinned key over another payload.

## Instances

<!-- use-case-instances:start -->
Each instance is a contract in `<scheme>/src/main.nr`, entrypoint `link(terms, evidence)`, package `<scheme>_login_link`, tested by `scripts/test-use-cases.sh login-link/<scheme>`. Its `src/test.nr` has the tests `valid`, `wrong_challenge_rejected`, `stale_rejected`; [use-cases.json](../use-cases.json) records each exception and its reason. The category is the evidence category of [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).

| Instance | Category | Contract | Adapter | Residual risk and notes |
| --- | --- | --- | --- | --- |
| [apple](apple/src/main.nr) | 3 | `AppleLoginLink` | [`uc_adapter_apple`](../adapters/apple/src/lib.nr) via `OidcLink` | `sub` is per developer team; one person can hold several Apple Accounts. |
| [entra](entra/src/main.nr) | 3 | `EntraLoginLink` | [`uc_adapter_entra`](../adapters/entra/src/lib.nr) via `OidcLink` | `sub` is pairwise per application (not the tenant-wide `oid`). Tenant administrators can issue tokens for any of its accounts, and a guest's token is a tenant token too: a link shows no membership. |
| [ethereum_siwe](ethereum_siwe/src/main.nr) | 1 | `EthereumSiweLoginLink` | [`uc_adapter_ethereum_siwe`](../adapters/ethereum_siwe/src/lib.nr) | Identity: the Ethereum address, the same in every app. Contract wallets (EIP-1271) cannot link. The holder's wallet states `Issued At` and `Expiration Time`. A message with a statement, request id, not-before or resources field does not verify. |
| [facebook](facebook/src/main.nr) | 3 | `FacebookLoginLink` | [`uc_adapter_facebook`](../adapters/facebook/src/lib.nr) via `OidcLink` | `sub` is an app-scoped user id: one per user per app. |
| [franceconnect](franceconnect/src/main.nr) | 3 | `FranceconnectLoginLink` | [`uc_adapter_franceconnect`](../adapters/franceconnect/src/lib.nr) via `OidcLink` | `sub` is a pairwise pivot subject per client; one per person is unconfirmed. The minimum eIDAS level is part of the issuer pin. The host decrypts the JWE; the circuit verifies the inner signed token. |
| [google](google/src/main.nr) | 3 | `GoogleLoginLink` | [`uc_adapter_google`](../adapters/google/src/lib.nr) via `OidcLink` | `sub` is one per Google account, the same for every client. |
| [govbr](govbr/src/main.nr) | 3 | `GovbrLoginLink` | [`uc_adapter_govbr`](../adapters/govbr/src/lib.nr) via `OidcLink` | `sub` is the CPF (11 digits, national): anyone can compute the link nullifier of every CPF and learn which CPFs linked in this app, and when. Do not deploy where that is unacceptable; a keyed or blinded identity is needed. Tokens live 60 s. |
| [jpki](jpki/src/main.nr) | 2 | `JpkiLoginLink` | [`uc_adapter_jpki`](../adapters/jpki/src/lib.nr) | Identity: the card's authentication key (SPKI hash), per card; a new card or renewed certificate links as another identity. The certificate carries no name. Card middleware chooses the challenge and the card does not show it. The issue time is holder-stated; the OCSP window bounds use. Anchor class 1 is a local test root. |
| [kakao](kakao/src/main.nr) | 3 | `KakaoLoginLink` | [`uc_adapter_kakao`](../adapters/kakao/src/lib.nr) via `OidcLink` | `sub` is the service-user id of the app. |
| [line](line/src/main.nr) | 3 | `LineLoginLink` | [`uc_adapter_line`](../adapters/line/src/lib.nr) via `OidcLink` | `sub` is one per LINE account per provider. ES256 only: web-login HS256 tokens are refused. |
| [linkedin](linkedin/src/main.nr) | 3 | `LinkedinLoginLink` | [`uc_adapter_linkedin`](../adapters/linkedin/src/lib.nr) via `OidcBearerLink` | Bearer: LinkedIn® tokens have no nonce, so the link is not bound to the caller and any holder of a copy (LinkedIn®, the client, a log or proxy) can link the subject to their own address until the 4-hour ceiling or `exp`. Needs `allow_bearer`; prefer a provider with a nonce. `sub` is treated as pairwise; unconfirmed with a provider token. |
| [miargentina](miargentina/src/main.nr) | 3 | `MiargentinaLoginLink` | [`uc_adapter_miargentina`](../adapters/miargentina/src/lib.nr) via `OidcLink` | `sub` is opaque; its semantics are unconfirmed. |
| [passkey](passkey/src/main.nr) | 1 | `PasskeyLoginLink` | [`uc_adapter_passkey`](../adapters/passkey/src/lib.nr) | Identity: the P-256 key, one credential at one relying party. A synced passkey's sync provider also holds the key; no `ALSO_*` bit reports it. A software key can set any flags. The issue time is holder-stated. |
| [singpass](singpass/src/main.nr) | 3 | `SingpassLoginLink` | [`uc_adapter_singpass`](../adapters/singpass/src/lib.nr) via `OidcLink` | `sub` is one Singpass account for the client; one per person is not established. Production requires assurance 2 or more. The host decrypts the JWE; the circuit verifies the inner signed token. |
| [telegram](telegram/src/main.nr) | 3 | `TelegramLoginLink` | [`uc_adapter_telegram`](../adapters/telegram/src/lib.nr) via `OidcLink` | `sub` is opaque; per bot or global is unconfirmed. If it is the integer user id, anyone can compute the link nullifier of every id, as with the gov.br CPF. |
| [twitter_reclaim](twitter_reclaim/src/main.nr) | 4 | `TwitterReclaimLoginLink` | [`uc_adapter_twitter_reclaim`](../adapters/twitter_reclaim/src/lib.nr) | Identity: the lowercased X handle at login time, not the account (renames, released handles). The circuit cannot tell a sound template from an unsound one: no reviewed X template exists, and the fixture's `contains` rule is a synthetic illustration not to copy. The attestor does not check the prover-written `providerHash`. |
| [university](university/src/main.nr) | 3 | `UniversityLoginLink` | [`uc_adapter_university`](../adapters/university/src/lib.nr) via `OidcLink` | `sub` is one CILogon user, the same for every client; one person can hold several (one per upstream IdP). CILogon asserts the campus `idp`. |
| [zkemail](zkemail/src/main.nr) | 3 | `ZkemailLoginLink` | [`uc_adapter_zkemail`](../adapters/zkemail/src/lib.nr) | Identity: the From mailbox; the domain can reassign it and one person can hold several (aliases, `+tags`, provider spellings). The profile signs only relaxed `from:to:subject`; providers that sign more headers do not verify. The recipient is not pinned: whoever gets the user to send another caller's challenge links the mailbox to that caller. |
| [zupass](zupass/src/main.nr) | 2 | `ZupassLoginLink` | [`uc_adapter_zupass`](../adapters/zupass/src/lib.nr) | Identity: the holder key, the same in every app. The issue time is holder-stated, and the POD has no expiry, so a revoked ticket still links. A raw `signPODRoot` signer, or an app API that signs app-chosen entries, is a login oracle: holder software must not sign `_aztec_link_v1_` PODs for another party. |
<!-- use-case-instances:end -->
