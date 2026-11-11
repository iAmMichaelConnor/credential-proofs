# Use-case architecture and evidence contracts

The [README](README.md) lists the use cases and their instances. This
document holds what they share: what each kind of evidence establishes, the
trust and binding contract between adapters and cores, the rules and risks
that are written once, the package layout, the generator, the tests and the
authoring rules. [use-cases.json](use-cases.json) defines the instances;
[docs/SECURITY.md](../../docs/SECURITY.md) explains credential authority.

A library ([`noir/`](../../noir)) verifies a bounded credential or signature. An
adapter (`adapters/<scheme>/`) adds the application policy (trusted issuer
pins, subject identifiers, action bindings) and translates verified evidence
into a use-case claim; import the library directly to use its verifier
without that policy. Generic cores apply the common trust, binding,
freshness and replay rules and import no scheme library. Instance contracts
commit to their policy and choose a fixed effect, or execute an authorised
account payload.

## Evidence and authority

| Category | Evidence | Authority boundary |
| --- | --- | --- |
| 1 User signature | The user's key signs, or the prover knows its secret. | The enrolled key controls the action. |
| 2 Certified key | An issuer certifies a key; its holder signs. | Certification alone proves no holder possession. |
| 3 Identity provider | An IdP signs a login, or a mail domain signs a message. | The IdP/domain and the client/mail operator remain co-authorities. |
| 4 Attestor | An external attestor signs an observed session or fact. | The attestor is trusted; a prover-chosen context is not holder approval. |
| 5 Payment event | A platform or attestor signs payment facts. | A merchant field does not establish payer approval of an arbitrary action. |
| 6 Static document | An issuer signs a document. | Anyone with a copy may present it. |

`uc_trust` also has labels for chain (7) and proof-system (8) evidence; no
instance here uses them. Such evidence would establish the verified state,
event or relation under its anchor or public-input policy, not personhood.

## Trust carried by every claim

Every claim has a `Trust` ([`uc_trust`](trust/src/lib.nr); byte encodings in
[bytes.nr](trust/src/bytes.nr)):

| Field | Meaning |
| --- | --- |
| `source` | Who produced the evidence: user key (1), certified key (2), identity provider (3), attestor (4), payment platform (5), document issuer (6), chain (7), proof system (8). |
| `issuer` | Poseidon2 of the trusted key, attestor, platform key, registry or chain id; 0 for user keys in accounts, and the relying party pin for user keys in login links. |
| `anchor_kind`, `anchor` | For evidence under an authenticated root: how the root reaches Aztec (pinned or registry) and the root itself; `ANCHOR_NONE` for every adapter here. L1-message and light-client anchors are not implemented, and the cores reject them. |
| `finality` | Blocks below the anchor. |
| `also_authorised` | Bitmask of parties other than the holder that can produce valid evidence: IdP, OIDC client operator, mail operator, attestor, merchant, copy holder. |

A claim that binds a value carries a `Binding`: the value and who chose it
(`set_by`: none, holder, OIDC client, mail sender, any prover, merchant,
payer). The login-link, gating, uniqueness, settlement and event terms hold
a `TrustPolicy`; those cores compare source, issuer and anchor kind for
equality, the anchor for pinned kinds, finality with a minimum, and
`also_authorised` only against refused bits, so evidence with different
trust is never interchangeable. `uc_account` has no `TrustPolicy`: the
adapter's policy, which the account address commits to, pins the trusted
key, and the core checks source, binding and the copy-holder bit.

All of these checks read the labels that the adapter reports, and a wrong
label (a bolted-on key reported as `SOURCE_USER_KEY`, bearer evidence
without `ALSO_COPY_HOLDER`) passes them. Adapter review checks the labels;
read an adapter's `src/lib.nr` before relying on its profile. Account
admissibility requires action-carrying evidence from categories 1 to 4: a
separately enrolled key cannot turn a payment, static document or bearer
token into account authorisation.

Issuer keys, enrolled identities and application terms need authenticated
policy: a deployer takes each key from the issuer's published key set or
certificate through an authenticated channel, never from the evidence.
Freshness checks and the requested transaction expiration are separate from
rollup inclusion enforcement.

## Rules written once

| Rule | Where | What it does |
| --- | --- | --- |
| Trust acceptance | `uc_trust::assert_trust_accepted` | Source, issuer, anchor kind, pinned anchor, minimum finality and refused co-authorities. |
| Freshness | `uc_trust::require_fresh` | Rejects evidence issued after the anchor block or older than `max_age` at it, and limits inclusion to `issued_at + max_age`. |
| Bearer ceiling | `uc_trust::effective_max_age` | Evidence labelled `ALSO_COPY_HOLDER` gets at most `MAX_BEARER_AGE` (4 hours: the upstream AnonAadhaarVote 3 hours plus IST-hour truncation). Undated evidence accepted under `allow_undated` has no ceiling. |
| Caller binding | `uc_trust::caller_binding` | Evidence must bind Poseidon2(domain, chain id, version, contract, caller), so a stolen proof is useless to another caller. Unbound evidence needs `allow_unbound`. |
| Free choice | `uc_trust::assert_choice_allowed` | A free argument (a vote choice) is taken only from evidence that the holder, the holder's OIDC client or the mail sender bound. |
| Replay | `uc_trust::scoped_nullifier` | Poseidon2(domain, scope, id) with a hashed domain tag per use case. |
| Term binding | `uc_trust::bind_terms` | The contract's `immutables_hash` must equal Poseidon2(terms domain, scheme, Poseidon2(terms)). |

Each core function first binds its terms to the contract, then applies the
rules. A `*_with_bound_terms` variant (for accounts,
`entrypoint_with_bound_policy`) skips only the term binding, for a caller
that authenticates the terms in another way; calling it without that check
lets any terms through.

## Residual risks shared by every use case

- OIDC evidence: the identity provider and the client operator that picks
  the nonce can also authorise, and the consent screen does not show the
  action or challenge.
- Copy holders (U1b): anyone who holds a copy of bearer evidence (a hotel
  that received an Aadhaar QR) can act first. The effect is fixed, so they
  cannot redirect it, but they can use up the one-per-subject action.
- Nullifiers are siloed per contract: one-per-subject holds per contract and
  scope. A key rotation or a new pinned root needs a new deployment, which
  starts with an empty nullifier set.
- Every nullifier is a keyless function of its subject (identity, mailbox,
  key, credential, log): anyone who knows the subject can test whether it
  acted in an app. An enumerable subject (the gov.br CPF) exposes them all.
- ES256 accepts both `s` and `n - s`. The ES256 instances key their
  nullifiers on the subject, never on the signature, so the second form
  cannot act again.
- Fixtures are synthetic: tokens, mails, QRs, PODs, blocks and attestations
  under public test keys (`fixtures/manifest.json` records each key's
  provenance), not provider credentials. They establish test scenarios, not
  interoperability with a provider.
- The instance tests (`src/test.nr`) run the core and the adapter at a keyless
  shell contract. The instance contracts are type-checked, not compiled or
  executed, so their effects and the calls of an account payload do not run.
  No test makes a proof (see [Testing](#testing)).

## Scheme-by-use-case eligibility

An absent scheme/use-case pair has no instance; listing a scheme elsewhere
does not promise an implementation or establish that a combination is sound.
User and certified holder signatures support action approval and
challenge-bound links; nonce-bearing OIDC and action-mail profiles add their
co-authorities. Issuer-signed fields support attribute gates only under
their specific claim semantics. Bearer tokens (LinkedIn®), payments, events
and static documents never authorise an account. A provider adapter
declares the use cases its evidence supports: Google's `sub` is one per
account for every client, so Google is no uniqueness source. Credential
identifiers are not person identifiers, and no Aadhaar, government-eID or
World ID uniqueness instance is implemented.

## Package layout

```text
aztec/use-cases/
  use-cases.json          the generator's source: use cases, adapters, instances and their notes
  package.json            npm dependencies of the fixture generators (own lockfile)
  trust/                  uc_trust: trust vocabulary and shared rules
  <use-case>/README.md    rules, residual risks, generated instance table
  <use-case>/common/      uc_<use_case>: trait, claim, terms, rules, unit tests
  <use-case>/<scheme>/    one generated instance contract (below)
  adapters/oidc/          uc_family_oidc: OidcProviderInput and the OIDC wrappers
  adapters/<scheme>/      uc_adapter_<scheme>: input structs and trait impls
  testing/                shared Noir test support (no instance may depend on it)
    core_tests/           uc_core_tests: TXE tests of the cores with dummy evidence
    dispatch_target/      uc_dispatch_target: deploy tests of the ethereum_secret_key account's dispatch
    family_oidc_tests/    uc_family_oidc_tests: TXE tests of the OIDC wrappers
    terms_shell/          uc_terms_shell: keyless contract that every TXE test deploys
    test_adapter/         uc_test_adapter: fail-closed evidence for the template checks
    template_<use_case>/  generated template checks: each contract shape type-checks
  scripts/                generate.py, check_fixtures.py, test-use-cases.sh
    templates/            templates of the generated files
    fixtures/generators/  fixture generators, one per scheme family
    tests/                unit and golden tests of the scripts
```

Every package is a member of the Aztec workspace (`aztec/Nargo.toml`, the
block after `# Use cases`, which the generator writes). Instances and adapters
depend on `aztec` by its `v6.0.0` git tag and on the credential libraries by
path (`../../../../noir/<package>`).

Instance directory (`<use-case>/<scheme>/`):

```text
  Nargo.toml              generated
  src/main.nr             generated contract; its header carries the row's notes, and only
                          its HAND-WRITTEN regions are edited
  src/test.nr             hand-written TXE tests with the required test names
  src/fixture.nr          written by a fixture generator (scripts/fixtures/generators)
  fixtures/manifest.json  fixture provenance (schema uc-fixture-v1)
```

## Generated files

[scripts/generate.py](scripts/generate.py) writes each instance's
`Nargo.toml` and `src/main.nr`, the instance table of each use-case README (with each row's `notes`), the grid
of the README and the use-case members of the Aztec workspace in
`aztec/Nargo.toml`. It keeps hand-written regions, adapters, cores, tests,
fixtures and prose outside the generated blocks, and formats the Noir it
writes with `nargo fmt` and [`aztec/noirfmt.toml`](../noirfmt.toml) (the nargo
of Aztec 6.0.0: `$NARGO`, else `aztec-nargo` or `nargo` on `PATH`). `--check`
writes nothing and rejects drift or invalid fixture and test metadata.
`--list` prints every package with its role for the test script. Generation
does not establish credential validity,
constraint satisfaction, proof verification or a mined transaction. Fixture
generators create the committed inputs and manifests; expected values are not
manufactured from the implementation.

## Testing

The instance contracts are examples. CI type-checks them with
`aztec-nargo check --workspace` in `aztec/`; by default no test compiles or
deploys one.
[scripts/test-use-cases.sh](scripts/test-use-cases.sh) runs the TXE tests. It
needs the Aztec 6.0.0 toolchain (`aztec`, `aztec-nargo`, `aztec-bb`) and runs
from anywhere. It compiles the keyless `testing/terms_shell` and runs
`bb aztec_process` on it once, unless its artifact in `aztec/target` is newer
than its sources; then it starts up to 12 TXE servers on ports from
`$TXE_PORT` (default 8081; [scripts/txe-server.mjs](../../scripts/txe-server.mjs) at the repository root
starts the Aztec CLI's TXE with a one-hour HTTP keep-alive, because the TXE
drops a test's session when its socket idles past Node's 5 s default during
long unconstrained code) and runs the selected packages' `nargo test`, up to
`--jobs` at once (default: cores / 4), each with `--test-threads` test threads
(default `$TEST_THREADS`, else 16; CI runners pass 4). Logs go to
`aztec/target/use-cases-logs/`:

```sh
aztec/use-cases/scripts/test-use-cases.sh cores                     # trust, cores, core and OIDC family TXE tests
aztec/use-cases/scripts/test-use-cases.sh adapters                  # adapter unit tests
aztec/use-cases/scripts/test-use-cases.sh login-link                # every instance of a use case
aztec/use-cases/scripts/test-use-cases.sh account-authorisation/google
aztec/use-cases/scripts/test-use-cases.sh --unconstrained-contracts account-authorisation/ethereum_secret_key
aztec/use-cases/scripts/test-use-cases.sh                           # everything
```

An instance tests what its scheme adds: the valid evidence, the scheme's own
checks (signature, key and issuer pin, claims, the challenge or action
binding, the reported times and expiry) and one rejection per check. Rules
that do not depend on the evidence are tested once, in `testing/core_tests`.
Boundary variants, fixture diagnostics and extra rejection cases go into
`mod release` at the end of `src/test.nr`.

The TXE tests run each core inside a TXE private context at a deployed
`uc_terms_shell` instance whose `immutables_hash` each test chooses, so term
binding reads a real contract instance. The shell has no functions, so
`bb aztec_process` generates no verification key for it. The tests call the
core as the generated entrypoint does, with the same arguments; the
entrypoint's ABI encoding, the instance's effect and the calls of an account
payload do not run (TXE refuses contract calls inside a private context).
TXE does not apply the rollup's transaction-expiry check; the tests read the
expiry that the core requests.

With `--unconstrained-contracts`, when `account-authorisation/ethereum_secret_key`
is selected, the script also compiles that account and `testing/dispatch_target`
as Brillig (`aztec-nargo compile --force-brillig`, then `bb aztec_process`) and
runs the deploy tests in `testing/dispatch_target`: they deploy the account and
call its `entrypoint` through the ABI with a payload whose call runs on the
deployed target, as the account (`msg_sender`), only after the credential
check, and once per transaction nonce. These artifacts are for tests only and
must never be deployed; their addresses differ from those of constrained
builds. The scheme signs nothing, so the test's credential is not bound to the
account's address.

Tooling checks (Python 3 standard library; the generator also needs nargo):

```sh
python3 aztec/use-cases/scripts/generate.py --check            # generated files and lint
python3 -m unittest discover -s aztec/use-cases/scripts/tests  # golden, drift, lint and format cases
python3 aztec/use-cases/scripts/check_fixtures.py --check      # regenerates every fixture and compares
```

`check_fixtures.py` runs the generators recorded in each
`fixtures/manifest.json` in a private copy and compares the outputs byte for
byte. It needs `npm ci` in `aztec/use-cases`, a built
[`packages/credential-proofs-inputs`](../../packages/credential-proofs-inputs) (`npm ci &&
npm run build`, also in its `tests/builders`) and the Python `cryptography`
package; the generators make no proof and read no network.

## Notes for instance authors

1. Add the adapter (if new) and the instance row to `use-cases.json`
   (`use_case`, `scheme`, `adapter`, `category`, `txe`, and `choice`,
   `bearer`, `skip_tests` or `notes` where they apply). A
   provider adapter declares the use cases its evidence supports in
   `use_cases` (and `bearer_use_cases` for a provider without a nonce
   claim); the generator refuses any other row. Instances cannot use the
   test adapter or depend on `testing/`.
2. `notes` lists the instance's own residual risks and caveats, one line
   each: what it trusts or cannot prove beyond its category README (for
   example an enumerable subject). Instances have no README; the lint
   rejects one.
3. Run `python3 scripts/generate.py`.
4. Write `src/test.nr` with the required test names (listed above each
   instance table) and build the fixture with a generator in
   `scripts/fixtures/generators`. A fixture that models a provider token uses
   the provider's real lifetime (`exp - iat`). Generated sources and
   fixtures are `nargo fmt` clean; run `nargo fmt` once on a new
   `src/test.nr` and the hand-written regions.
5. The lint requires `#[test(should_fail_with = "<message>")]` on every
   `*_rejected` test, a named failure on any other test that expects one, no
   expected failure on the other required tests, and required bodies that
   call a function other than an assertion and do not assert a constant
   false. The lint cannot show that a test fails for the stated
   reason; the reviewer checks that (`should_fail_with = "<any text>"`
   makes nargo print the message it got and the assertion's location).
6. A HAND-WRITTEN region must not add an `#[external]` (or `#[private]`,
   `#[public]`, `#[utility]`, `#[initializer]`) function under any path or
   alias, and must not shadow a name that the generated code uses: the
   generated entrypoint is the only one. A function generated by a custom
   macro is not detected; the reviewer checks the regions.
7. `python3 scripts/generate.py --check`, `aztec-nargo check --workspace`
   in `aztec/` and `scripts/test-use-cases.sh <dir>` must pass.

The OIDC family: a provider adapter implements
`uc_family_oidc::OidcProviderInput` (scheme id, policy hash, and `verify`
under the pinned key with the exact nonce). The generated entrypoint wraps
the provider input (`OidcLink { input: evidence }`), so the wrapper is never
part of the ABI. `OidcLogin.issuer` must pin the key, the issuer and the
client id together (and any provider policy, such as a tenant, environment
or minimum assurance level), and `OidcLogin.subject` must hash only the
bytes within the subject's length. A provider without a nonce claim
(LinkedIn®) refuses every nonempty nonce and is used only through
`OidcBearerLink`, which requires `SignedIssueTime`: `OidcLogin.issued_at`
must be the signed `iat`, and an adapter that derives it (for example `exp`
minus a lifetime) must not implement it.

- Entrypoints cannot be generic: each instance has a concrete entrypoint of
  a few lines that calls the core.
- Adapters own their input structs and implement the core trait on them
  (orphan rule). Crates that depend on `aztec` are named `uc_*` and sort
  after `aztec`, so that ABI struct paths print as `aztec::...`.
- Account addresses commit to the contract artifact, including bytecode and
  ABI. Moving input structs or changing the core call structure can change
  the class and address even when the relation accepts the same inputs.
- Policy or terms serialization and the scheme enter the instance's
  immutable commitment; core entrypoints verify supplied terms against it.
  Entrypoint parameter names and layouts are part of the consumer contract.
