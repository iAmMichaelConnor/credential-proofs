# Credential security and composition

The packages in [`noir/`](../noir/) verify cryptographic relations. The
consuming contract decides which keys, issuers and claims authorize which
action. The [README](../README.md#what-is-in-the-repository) lists, per credential, what
a holder must possess, who chooses the bound value, whom the consumer trusts and
what it must consume; each package's `src/lib.nr` states its own caller
obligations. Application examples are in [`aztec/use-cases`](../aztec/use-cases/README.md).

## Authority

A signature under an authenticated user key or certified holder key can
authorize an action. An action-bound identity-provider token also trusts the
issuer and the enrolled client that chooses its nonce. An attestation trusts
its attestor. Payment evidence, static documents and bearer tokens do not
establish authority over an arbitrary account action, and adding a separately
enrolled key does not change that: the key would do all the authorizing and the
credential would only be a gate. Use such credentials with a fixed effect
(attribute gating, uniqueness, payment settlement, event proof), with the
effect, recipient and replay policy fixed so another copy holder cannot
redirect it. A copy holder can still act first and consume a one-time claim.

A malicious page that uses the enrolled OIDC client can obtain a token for any
action when the user logs in, possibly silently under single sign-on. Login,
consent, PIN and authenticator screens show the client or relying party, not
the Aztec action: the software requesting approval must compute the action from
the actual chain, contract, account and payload and show it to the user.

## Binding obligations

Values described as "expected" must come from trusted policy, never from
unchecked prover input. Bind authorization to a domain-separated digest of the
chain, account, action or call payload and a one-use nonce; session
authorization also binds scope and expiry. The contract constrains the trusted
current time and consumes the nonce or nullifier. Signing a nonce without
binding the recipient or action permits substitution. Derive replay identifiers
from the authenticated request or message identity, not from a malleable
signature encoding. Credential expiry and maximum age must also bound the
transaction's inclusion time.

When `now` is the anchor block timestamp it lags wall-clock time: a credential
stamped after the anchor block is rejected until a newer block is anchored,
and then passes while it is within its window. Set every maximum age or expiry
well above block lag plus proving time.

Anchor issuer keys through a maintained registry or committed account policy: a
valid JWT, DKIM signature or attestation under a prover-selected key says
nothing about the provider. For OIDC, use the stable issuer/subject pair as
identity; expiry, key rotation, revocation, nonce binding and enrollment remain
separate concerns. For DKIM, anchor the key to the intended domain, selector
and validity period, and give the account its own exact message template,
challenge, recipient, expiry and replay rules ([zkEmail limits](zkemail.md)).

The benchmark function of each package (`src/benchmarks.nr`) is the complete
relation its known-answer tests run, with the trusted key and every expected
value as an argument. It demonstrates the relation; it is not a deployed account
or a measurement of an Aztec transaction.

Signed-JSON importers reject a leading UTF-8 BOM rather than discarding bytes
still present in the witness. The host JSON helper rejects duplicate keys at
every depth; Noir OIDC protects the authority-bearing root claims and the
direct assurance level, and may accept duplicate unrelated nested keys.

## Dependency domains

Exact Git tags are declared in the Nargo manifests (the README lists the two
dependencies tracked at `main` and their tested commits). A dependency change
must keep these accepted domains and checks:

- RSA: SHA-256 and SHA-512 digests and 1024/2048/4096-bit widths. Key identity
  is the modulus; Barrett hints are never key identifiers or replay inputs. The
  18x120-to-17x121 conversion rejects values above its 2057-bit output domain;
  the full-width conversion keeps all 2160 input bits. Folding range-checks
  every input.
- Ed25519 ([`vendor/noir-ed25519`](../vendor/noir-ed25519/)): verification uses
  the scalar-63 path after independent prime-subgroup checks, not the
  dependency's incomplete scalar-64 path. Canonical encodings and a nonidentity
  issuer key are required, while a valid identity `R` and `S = 0` stay
  accepted; do not replace this with blanket nonzero checks.
- Zupass (noir-edwards `main`, which contains noir-edwards #55): the signature
  scalar uses the scalar-63 path and the challenge a bitwise ladder; see
  [Zupass](zupass.md).
- Base64url: the helper checks canonical active length and unused tail bits
  itself and does not use the pinned dependency's variable encoder.
- P-256 and secp256k1 black boxes: the pinned witness solver and backend reject
  a few valid exceptional signatures (completeness only); see
  [`noir/p256_auth/src/lib.nr`](../noir/p256_auth/src/lib.nr). Recheck after a nargo or
  bb pin change.

## Ethereum secret key

The secret key is exactly 32 big-endian bytes, constrained by
`Secp256k1_Fr::from_be_bytes` and `validate_in_field` to `1 <= k < n` with
`n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`. The
generator ladder uses BigCurve's complete `Add` for every doubling and
conditional addition, not the offset-based `mul`, whose incomplete additions
need a distinct-x precondition that is not established for every admissible
scalar. The ladder reduces modulo `n`, so only the range check rejects `n + 1`
or `2^256 - 1` presented with the address of their residue; the argument is in
[`secret_key.nr`](../noir/ethereum_auth/src/secret_key.nr). This proves knowledge of
a scalar bound to an address, not control of a SIWE session or account policy.

## Aadhaar Secure QR nullifier

```text
name_chunk[j] = big-endian pack of name bytes 31j .. 31j+30, zero after the name (j = 0..4)
identity      = Poseidon2([IDENTITY_DOMAIN, aadhaar_last4, birth_year, birth_month, birth_day,
                           name_length, name_chunk[0..5]])
nullifier     = Poseidon2([NULLIFIER_DOMAIN, app_seed, identity])
```

The inputs exclude the photo, issuance time, address, mobile digits, gender and
issuer key, so the nullifier survives a photo update, a new QR download, a move
and a key rotation; it changes only when UIDAI changes the name, date of birth
or Aadhaar number. It is not compatible with Anon Aadhaar's photo nullifier.

- **Collisions.** Holders with the same name bytes, recorded birth date and
  last four digits share a nullifier, and the second is blocked (completeness,
  not double use). Approximate birth dates such as 01-01-YYYY make this common
  for frequent names: in a group of `k` such holders some pair collides with
  probability about 50% at `k = 118`.
- **Linkability.** Anyone who knows a person's name and birth date computes the
  10,000 candidates under the public seed in seconds and checks the app's
  public nullifier set; with the last four digits (printed on masked copies),
  one hash suffices. Seeds and contract siloing do not help. Treat
  participation in a uniqueness app as public and linked to name and birth
  date; do not use this nullifier where participation must stay private. The
  upstream photo nullifier resists this search but changes with the photo, QR
  or key, so one person can obtain several: the deployer chooses between the
  two trade-offs.

## Validation scope

Noir regressions exercise accepted boundaries and malformed inputs; SDK tests
check input preparation and host policy checks. Execution validates the
constrained relation it runs. Neither TXE tests nor witness execution verify an
Aztec transaction or a recursive proof, and none of these tests is an audit.
