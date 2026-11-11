> **Experimental software. Unaudited. May contain bugs.**

# World ID uniqueness in Aztec

World ID application semantics and proof formats are separate version axes.
The World ID packages check World ID 3 Semaphore and World ID 4 nullifier proofs
with the runtime-key Groth16 verifier of
[groth16-verifier](https://github.com/iAmMichaelConnor/groth16-verifier)
(`runtime_verifier`, tag v0.1.0), bind each proof to an application context and
apply the version-specific root, issuer, expiry, action and uniqueness policy.
Policy checks alone do not verify a proof. World Chain transaction or storage
proofs are not integrated.

| Application profile | Source proof | Public inputs | Meaning |
| --- | --- | --- | --- |
| `world-id-3-semaphore` | BN254 Groth16, Semaphore | 4 | Membership under an approved identity root; one claim per World ID identity and external nullifier in each consuming contract; signal binding |
| `world-id-4-nullifier-v1` | BN254 Groth16, OPRF nullifier circuit | 15 | Credential/issuer checks, registry membership; one claim per registry account and RP/action in each consuming contract (issuer-independent); signal binding; nonce bound but not authenticated |

World ID uniqueness and World ID ownership are different claims; only the
uniqueness versions above are accepted. Saved fixtures cover both input
shapes; the Semaphore fixture uses a depth-16 test key and root. Production key
and root selection is the application's responsibility.

## Packages

- `noir/world_id_uniqueness`: the policy (`check_semaphore`,
  `NullifierPolicy`, `check_nullifier`) and `groth16`, the Groth16 adapter:
  `groth16::verify` checks a proof and compares the key hash with an authorized
  one; `decode_key` and `decode_hints` turn the flat contract arguments into
  `runtime_verifier` types. `src/benchmarks.nr` has the 4- and 15-input Groth16
  producer circuits as `#[export]` functions.
- `noir/world_id_common`: the context signal (`signal`), context-bound
  statements (`binding`) and the recursive certificate check (`certificate`).
- The World ID 3 and 4 gates and their TXE tests:
  [`aztec/world-id-v3`](../aztec/world-id-v3/) (`WorldId3Gate`) and
  [`aztec/world-id-v4`](../aztec/world-id-v4/) (`WorldId4Gate`). In each gate
  `claim` calls the library method `verify_claim`, which calls a shared
  `claim_with(context, public_inputs, beneficiary, nonce, verify)` that does the
  whole composition: the storage reads (through the contract's own
  `Storage::init`), the root-window and claim-time check, the verification step
  and `consume_claim`. The constructor's body is a library method too
  (`initialize_snapshot` in v3; `initialize_configuration` in v4, which calls
  `check_configuration`).
- `scripts/world-id/create_variant.py --backend groth16` writes a producer, a
  direct contract or a recursive consumer for any input count. It compiles and
  proves nothing; the generated consumer shows the key-binding rule of
  [Recursive certificate boundary](#recursive-certificate-boundary).
- The [TypeScript SDK](../packages/credential-proofs-world-id/README.md) (`credential-proofs-world-id`):
  strict encodings, policies and Groth16 codecs. Its checks, including
  `checkClaim`, are preflight diagnostics, not proof verification; on-chain
  acceptance needs the proof, the constrained policy and the state effect.

### Groth16 verification

`groth16::verify` calls `runtime_verifier::verify`, which keeps every point,
scalar, line and pairing constraint in the circuit. Both gates and both
producer benchmarks use it, and everything here builds, proves and tests with
stock nargo and bb 6.0.0.

## Tests and fixtures

From the repository root (see CONTRIBUTING.md for setup):

```sh
./scripts/run-tests.sh --package world_id_uniqueness --package world_id_common
python3 -m unittest discover -s scripts/world-id/tests -p 'test_*.py'
node --test scripts/world-id/tests/world_id4_input.test.mjs
npm test -w credential-proofs-world-id
TXE_PORT=8081 ./scripts/test-world-id.sh
node scripts/world-id/world_id_foundation.mjs --check
node scripts/world-id/world_id4_foundation.mjs --check
```

None of them creates a proof or a verification key, and none compiles or
deploys a contract. `./scripts/test-world-id.sh --unconstrained-contracts` also
compiles both gates unconstrained (test-only artifacts) and runs
`aztec/world-id-deploy-tests`, which deploys them and checks the constructor's
storage writes and the initialisation checks; it makes no claim, because no
deployed gate has the fixed test address the saved proofs bind. The gate tests run the gates' library methods in TXE
private contexts at a fixed test address and replay saved synthetic proofs
bound to that address, the chain id and version (1 in TXE), the policy,
action, beneficiary and nonce. Compiling the Groth16 verifier to Brillig is
far slower than compiling it to a circuit, so the constrained tests (the
accepted claim and the unpinned key) run the whole claim with the real Groth16
verifier as a circuit, and the others run `claim_with` unconstrained with a
stand-in verifier on the proof's public inputs.
TXE checks context effects (the expiration timestamp, repeated nullifiers in
one context and across blocks), not backend proof validation.
`scripts/world-id/world_id_foundation.mjs` (World ID 3) and
`world_id4_foundation.mjs` (World ID 4) write the test fixtures from the saved
proofs in `fixtures/world-id/aztec-*foundation.json`; `--check` fails if a
fixture is stale or the saved proof is not bound to the generator's signal
context. Both check the proof against its upstream key, and only
`--foundation-proof` creates a new one.

## Exact public-input schemas

Semaphore: `[root, nullifier_hash, signal_hash, external_nullifier_hash]`.
Its uncompressed Solidity proof is eight Fq coordinates, with G2 coefficients
in imaginary/real order. The shared verifier expects real/imaginary order;
`fromSolidityProof` performs that conversion. Never reduce coordinates modulo
Fq or public inputs modulo Fr to accept a noncanonical payload.

World ID 4 nullifier:

```
nullifier, issuer_schema_id, issuer_key_x, issuer_key_y,
expires_at_min, credential_genesis_issued_at_min, root, tree_depth,
rp_id, action, oprf_key_x, oprf_key_y, signal_hash, nonce, session_id
```

`decompressWorldIdProof` decodes the four compressed Groth16 words. In the
five-word World ID transport, the fifth word is the registry root and must
populate public input 6; it is not a proof coordinate. The codec uses upstream's
square-root/sign convention and Noble arithmetic. Complete point/subgroup and
pairing checks come from the shared verifier. This adapter currently accepts
**uniqueness** claims: session ID must be zero and action must fit 248 bits.
Session verification is deliberately a different policy, not a uniqueness
claim with a different label.

## Application policy

No proof authenticates its own root or verification key. `checkClaim` and
`noir/world_id_uniqueness` take trusted policy as a separate argument. The example Aztec
contracts store the selected key, root, action and policy in `PublicImmutable`
configuration installed by the deployer. That is an explicit, expiring root
snapshot, not an implemented cross-chain root synchronization protocol.

World ID 4 policy also authenticates issuer schema/key, OPRF key, relying party,
tree depth, action and credential freshness bounds. Expiry is compared with the
anchor timestamp and used to cap transaction expiration, so a proof cannot
remain usable indefinitely by selecting an old anchor. The root snapshot also
caps transaction expiration. The policy requires `expires_at_min` to be at or
after the anchor time; it has no grace interval like upstream
`_minExpirationThreshold`.

### World ID 4 policy domain

`NullifierPolicy::from_fields` decodes the 11-field policy and rejects values
outside their domain; `check_nullifier` validates the policy again.
`WorldId4Gate` applies the decoder in its constructor and in every claim.

- `issuer_schema_id`, `rp_id`, `tree_depth`, `min_expiry` and `min_genesis`
  must be canonical u64 values ("Policy integer range").
- Public input 5 (`genesis_issued_at_min`) must be below 2^64 ("Genesis
  range") before the `min_genesis` comparison. Upstream `LessEqThan(64)`
  accepts every `gmin` in `[0, g]` and also in `[p - 2^64 + g + 1, p)`, with
  `p` the BN254 scalar modulus. Upstream is safe because the relying party
  writes `pubSignals[5]`. Here the prover supplies it, so `p - 1` passed every
  `min_genesis` before this check.
- `root` must be nonzero and `tree_depth` must be at most 30. Upstream
  `BinaryMerkleRoot(30)` outputs 0 for every depth outside `[0, 30]`, so root 0
  with such a depth accepts any leaf. Upstream enforces both outside the
  circuit (registry depth, `isValidRoot`).
- The issuer key coordinates must be nonzero and the action must fit 248 bits
  (top byte 0x00, as WorldIDVerifierV2). Session (0x02) actions are rejected.

### Expiry: set `expires_at_min` explicitly

The upstream request flow defaults `expires_at_min` to the request creation
time. That time is already past when the Aztec claim is included, so the gate
rejects such a proof ("Credential expiration bound too old"), or the
transaction expiration is in the past. A relying party request for this gate
must set `expires_at_min` explicitly: at least the latest intended inclusion
time (request time plus World ID proving, client proving and inclusion
latency) and at most the credential expiry. It caps the Aztec transaction
expiration, which the kernel also caps at anchor time + 24 hours.

### Root snapshot age

Each gate pins one root. Upstream `WorldIDRegistry` accepts the latest root,
or a superseded root for 3600 s (`_rootValidityWindow`). A pinned root has two
consequences:

- An authenticator removed, or an account recovered, after the snapshot stays
  claimable under the snapshot root until `valid_until` (revocation lag).
- Proofs under newer roots fail with "Unapproved root".

The gates do not cap `valid_until`. The Aztec nullifier is siloed to the gate
contract, so uniqueness holds per gate: a successor gate for the same action
starts with an empty nullifier set, and the same World ID can claim once more
there. A short-lived gate that is replaced on a schedule therefore trades
revocation lag for repeated claims; a cap on `valid_until` would force that
trade. Choose `valid_until` for the whole action (campaign) and accept the
revocation lag, or let a successor gate check its predecessors' nullifiers.
Upstream semantics (one nullifier space with an updatable root accepted for
3600 s after it is superseded) need an authorised root updater, which these
examples do not implement. The test fixtures use `valid_until = 1900000000`.

### Block 1

The rollup does not check a transaction's expiration timestamp in block 1,
which can only anchor to block 0 (timestamp 0 by default). For a gate
pre-deployed in a custom genesis, the anchor-relative and inclusion-time
bounds would not apply there. `WorldId4Gate` rejects a block-0 anchor
("Genesis anchor"). `WorldId3Gate` has no such check; on a canonical network
no gate can be initialized at genesis.

### Signal

`signalBytes(context)` returns raw bytes. A hexadecimal string is a transport
representation of those bytes, not the signal's UTF-8 text. Decode that
representation before hashing: hashing the characters of `0x` plus the hex
digits gives a different public signal hash and fails `checkClaim`. Match the
calling API's byte/transport contract; this does not prescribe a provider
version's transport format.

The signal supplied to World ID is exactly 224 bytes: seven big-endian 32-byte
words `[WORLD_ID_AZTEC_V1, chain, version, consumer, action, beneficiary, nonce]`.
Its hash is `uint256(keccak256(bytes)) >> 8`. `signalBytes` produces the client
bytes and the Noir policy reconstructs them from the actual Aztec context.
Changing any context field invalidates an existing proof. Binding does not
show who chose the beneficiary (see
[Request-path obligations](#request-path-obligations)). `externalNullifier(appId,
action)` implements the World ID 3 application/action hash convention; its
result must be selected by trusted application configuration.

## What a claim establishes

Read this section before you design an application on a gate. It states what
a claim does not give, and what the application and the request path must do.

### The Aztec nullifier

```
World ID 3: Poseidon2([DOMAIN + 1, 3, external_nullifier, nullifier_hash])
World ID 4: Poseidon2([DOMAIN + 1, 4, rp_id, action, nullifier])
DOMAIN = "WORLD_ID_AZTEC_V1"; the kernel then siloes it by contract address.
```

The nullifier excludes the root, beneficiary and nonce: a change to these must
not permit a second use of the same World ID nullifier. The World ID 4
nullifier also excludes `issuer_schema_id`. Upstream derives the
nullifier from the account, `rp_id`, `action` and the OPRF key only
(world-id-protocol@46f6b43
`circom/client_side_proofs/oprf_nullifier.circom:114, :172-173`), so one
account gets one nullifier per RP and action whatever credential it shows. A
policy that accepts several issuers therefore still allows one claim per
account. The gate checks the issuer against its policy before it emits the
nullifier. Poseidon2 binds the five-field input length in its initial state. Changing
the nullifier encoding changes the replay domain and requires a new campaign
with a new action.

Emitting the nullifier is essential; merely returning a verified claim does
not prevent replay. The private kernel only siloes the value. The base rollup
rejects a siloed nullifier that is already in the nullifier tree, or that
occurs twice in one transaction, when it inserts it into the indexed tree.
Private simulation is not the replay guarantee.

### Uniqueness scope: per gate contract

Duplicate rejection works on the siloed nullifier. The enforced property is
therefore one claim per World ID identity (v3) or registry account (v4), per
external nullifier (v3) or RP and action (v4), **per gate contract**:

- A second gate, or a redeployed gate, is a new uniqueness domain with an
  empty nullifier set. The same World ID can claim once more there, even with
  the same external nullifier or action.
- The gates do not check nullifiers spent at another gate or on Ethereum.
- The example gates keep root, policy and `valid_until` in `PublicImmutable`
  storage. A root refresh means a redeployment, which resets uniqueness (see
  [Root snapshot age](#root-snapshot-age)).

Run one long-lived gate per campaign. If a campaign needs a new root, add an
authenticated root or policy update path (for example `DelayedPublicMutable`
written by an authorised updater) and keep the nullifier formula unchanged.
For World ID 4, a new OPRF key gives every account a new World ID nullifier,
and a policy that accepts several OPRF keys allows one claim per key. Treat an
OPRF key change like a new campaign.
Do not add the gate address or the root to the nullifier: the root would
permit a second claim after each refresh. If you must deploy a new gate,
treat it as a new campaign and give it a new external nullifier (v3) or
action (v4), so that nobody reads two gates as one uniqueness domain.

### Identity, account and person

The circuits establish uniqueness per World ID **identity** (v3: one Semaphore
identity commitment under the pinned root) or per World ID **account** (v4:
one registry leaf, with a credential from the pinned issuer schema). They do
not establish that two identities or accounts belong to different people.

Person-level (Sybil) uniqueness is a property of World ID issuance, not of
these circuits:

- World ID 3: the pinned root must be a group that holds at most one identity
  per person (the Orb-verified group).
- World ID 4: registry accounts are permissionless (`createAccount` checks
  only a fee). The pinned issuer must issue its schema at most once per
  person. A policy that accepts several issuers needs every accepted issuer to
  meet this, and a person who holds credentials in two accounts can claim once
  per account.

The deployer must pin such a root or issuer. The repository fixtures use test
roots and keys; they are not production attestations.

### Linkability

The emitted nullifier is a public function without a key: of (contract
address, external nullifier, `nullifier_hash`) for World ID 3, and of
(contract address, `rp_id`, `action`, `nullifier`) for World ID 4. Anyone who
sees the World ID proof outputs for the same scope can compute it and find the
claim transaction, its beneficiary and its other public effects. Such parties
include a frontend that requests or relays the proof, a Developer Portal or
cloud-verify backend, `WorldIDRouter` calldata if the same app and action are
also verified on Ethereum, and an RP backend that receives the World ID 4
proof. A circuit cannot hide this: the gate never sees the World ID secret,
and a user-held salt would allow repeated claims.

- Use an app ID and action (v3), or an RP ID and action (v4), that only the
  Aztec gate uses. Never verify them elsewhere.
- Generate the World ID proof on the user's device and pass it straight to
  the PXE. A service that handles the proof learns the nullifier and the
  beneficiary in the signal.

### Request-path obligations

The gate binds the signal to `[chain, version, gate, action, beneficiary,
nonce]`, so an existing proof cannot be re-bound to another beneficiary or
gate. Signal binding does not show who chose the beneficiary. The path that
builds `signalBytes(context)` and asks the user for the proof is trusted:

1. A malicious or compromised frontend, extension or relay can request a proof
   whose signal names its own beneficiary. If the user approves it, the claim
   uses the user's single claim slot at that gate, and the user's own claim
   later fails as a duplicate.
2. World ID 4: the RP signature covers only the version, nonce, `created_at`,
   `expires_at` and action (world-id-protocol@46f6b43
   `crates/primitives/src/rp.rs:108-125`), not the signal. The OPRF nodes never
   see the signal, and World App does not show it. World ID 3: the app ID and
   action are public, so anyone can build a request.
3. Keep proofs and hints confidential until the claim is submitted. Anyone who
   holds them can submit first with the bound beneficiary and use the slot.
4. The gates read their own address, not `msg_sender`. If an application
   calls a gate from another contract, anyone who holds the user's proof can
   call the gate directly and use the slot without the application's effect. Put the policy check in the
   application contract (so its address is the bound consumer), or restrict
   callers.
5. Applications still need their own authorisation of the beneficiary.
   Enforce any RP approval of a beneficiary in contract state.

### The World ID 4 nonce

In the upstream nullifier circuit the nonce and signal hash are passthroughs:
they are public inputs with no constraint beyond dummy squares
(`oprf_nullifier.circom:186-189` at the same commit). The OPRF query and
output depend only on (account, `rp_id`, `action`). The OPRF nodes check the
RP-signed nonce when they evaluate, and an OPRF output can be reused. The
holder of one evaluation can therefore prove for any nonce and signal under
that RP and action without contacting the RP again.

- The gate checks that public input 13 equals the context nonce ("Wrong
  nonce"). This binds the nonce; it does not show that the RP issued it or
  that it is fresh. The nonce gives the gate no RP authorisation.
- With the stock Authenticator, the claim nonce must equal the nonce of the
  RP `ProofRequest`, and the request signal must be `signalBytes(context)`
  computed with that nonce. Otherwise the claim fails with "Wrong nonce" or
  "Wrong signal binding".
- The guarantee is one claim per account and action with a beneficiary that
  the holder chooses.

### Transaction phase

The gate emits its nullifier in the phase of the caller and does not check
the phase. A nullifier emitted after `end_setup` is revertible: if a public
call in the same transaction reverts, the nullifier is dropped. Effects in the
same phase are dropped with it, so the gate alone is safe. A non-revertible
effect that depends on the claim survives, and the claim can then be replayed
without limit. Such effects include fee-payer election or FPC sponsorship
(`set_as_fee_payer`), setup-phase public calls, and a teardown call whose
arguments come from the claim. If any such effect depends on the claim, call
the gate before `end_setup`. An account entrypoint calls `end_setup` before
the application calls, so the default flow is revertible.

## Recursive certificate boundary

`common::certificate::verify` uses proof type 6 with a pinned v6 backend. It
checks a one-field statement and requires a nonzero authorized producer key
hash. The backend must bind that hash to the supplied verification key and the
proof to that key. The recursive circuit returns pairing points; the final
transaction verifier discharges the deferred pairing and group operations.
Witness generation, local constraint checking or TXE execution does not
establish those checks.

An authorized producer key hash must be a compiled constant, authenticated
contract storage, or a public input that the outer verifier independently pins.
An unconstrained private witness grants no producer authority. The Groth16
producers accept the inner key hash privately and bind it in their public
statement, `groth16_statement(context, key_hash, inputs)`. A generated consumer
recomputes that statement with its stored `inner_key` and verifies the
certificate against its stored `producer_key`; both authorizations are required.
Accepting a prover-selected statement or inner key permits proofs under an
attacker-controlled Groth16 setup. `scripts/world-id/tests/test_certificate_binding.py`
checks the generated source boundaries, and Noir tests check the statement
bindings and that `groth16_statement` equals `runtime_verifier::statement_id`.

## Pinned primary sources

* [World ID 3 contracts](https://github.com/worldcoin/world-id-contracts/tree/f959f725c3ee2dec1ed24944d5b9593b68c7b8a4),
  especially the Semaphore verifier and identity manager public-input order.
* [World ID 4 verifier](https://github.com/worldcoin/world-id-protocol/blob/46f6b43d231780e4fc0b5030bd71e846664532d1/contracts/src/core/WorldIDVerifier.sol)
  and its V2 uniqueness/session action checks.

Source hashes and URLs of the extracted fixtures are in
[`fixtures/world-id/provenance.json`](../fixtures/world-id/provenance.json).
`scripts/world-id/import_world_id_fixtures.py` checks both upstream commits and
file contents before extracting keys. It un-negates Solidity verification-key
G2 Y coordinates; it performs no trusted setup and generates no proofs.
