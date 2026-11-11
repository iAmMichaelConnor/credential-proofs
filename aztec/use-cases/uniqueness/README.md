> **Experimental software. Unaudited. May contain bugs.**

# Uniqueness (U4 + U1b)

Statement: "this person has not done this in this app before; a fixed
effect happens". This directory provides the generic core and its tests; no
credential-specific instance or World ID adapter is implemented here (the
World ID gates live in [`aztec/world-id-v3`](../../world-id-v3) and
[`aztec/world-id-v4`](../../world-id-v4)).

Core crate: [`uc_uniqueness`](common/src/lib.nr) (`UniquenessEvidence`,
`UniquenessClaim`, `UniqueTerms { accepted, person_kind, max_age,
allow_undated, allow_unbound, scope }`, `once`, `once_with_choice`).

## Rules

1. `binding = Poseidon2(MIKE_UC_UNIQUENESS_BINDING_V1, chain_id, version,
   this_address, msg_sender[, choice])`.
2. Trust accepted; the person kind equals the terms and the person id is
   set. The adapter must justify that identifier's semantics.
3. Evidence with a free field must bind `binding`; unbound evidence needs
   `allow_unbound`.
4. `once_with_choice` takes the choice only from holder-chosen evidence; a
   static bearer document alone does not establish it.
5. Freshness as in [attribute gating](../attribute-gating/README.md#rules).
6. One action per person per contract: nullifier
   `Poseidon2(MIKE_UC_UNIQUENESS_V1, scope, person)`. `scope` separates
   actions within one contract and adds nothing across deployments.

## Residual risks

- Uniqueness holds per deployment only. A key rotation (for example UIDAI
  moves from K1 to K2) or a new pinned root needs a new deployment, whose
  nullifier set starts empty: everyone who acted at the old one can act
  again. Nothing here supplies a mutable root registry or a shared
  cross-deployment nullifier set.
- "Person" means what the issuer's id means: a World ID identity, an
  Aadhaar-derived nullifier, or an eID subject that is stable per client.
- A holder of a copy of bearer evidence (Aadhaar QR) can act first and use
  up the person's one action.
- The nullifier omits the scheme and the issuer. A `once_with_bound_terms`
  contract that accepts several issuers under one scope counts one person
  twice if the issuers give that person different ids.

## Tests

`common/src/tests.nr` covers the context-free rules. The TXE tests in
`../testing/core_tests/src/uniqueness.nr` cover a valid action, a second
action by the same person under a new root, another person, stale evidence,
a wrong person kind, a choice from holder-bound and prover-set evidence,
unbound and undated evidence refused and allowed, the requested inclusion
expiry, and at deployed keyless shells `once` and `once_with_choice` with
valid and wrong terms, a second action, and a second deployment of the same
terms where the same person acts again (the first risk above).

## Instances

<!-- use-case-instances:start -->
No instances yet.
<!-- use-case-instances:end -->
