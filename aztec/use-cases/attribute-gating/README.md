> **Experimental software. Unaudited. May contain bugs.**

# Attribute gating (U3 + U1b)

Statement: "a credential with attribute A was presented; a fixed effect
happens". The contract fixes the effect, so the outcome does not depend on
who submits. Static documents (Aadhaar QR, PhilSys QR) and PODs without a
holder signature cannot authorise an account; this is where they are used.

Core crate: [`uc_attribute_gate`](common/src/lib.nr) (`AttributeEvidence`,
`AttributeClaim`, `GateTerms { accepted, kind, predicate, threshold, max_age,
allow_undated, allow_unbound, scope }`, `gate`, `gate_with_choice`).

## Rules

1. `binding = Poseidon2(MIKE_UC_GATE_BINDING_V1, chain_id, version,
   this_address, msg_sender[, choice])`. The adapter puts it in the
   credential's free field, if it has one.
2. Trust accepted; `kind` equals the terms; the predicate (`EQ`, `GE`, `LE`
   on the value read as an integer) holds against `threshold`.
3. Evidence with a free field must bind `binding`; evidence without one needs
   `allow_unbound`.
4. `gate_with_choice` takes the choice only from evidence whose bound value
   the holder, the holder's OIDC client or the mail sender chose.
5. Freshness: `max_age`, capped at 4 hours for evidence labelled
   `ALSO_COPY_HOLDER`. Evidence with no time needs `allow_undated` and then
   has no freshness deadline and no cap.
6. One use per subject per app: nullifier `Poseidon2(MIKE_UC_GATE_V1, scope,
   subject)`. `subject` is an issuer-scoped person or credential id.

Each instance writes its effect in the HAND-WRITTEN `effect` region. The
effect has no free argument, and it gives something to an Aztec account only
when the evidence names that account under the control of someone other than
an arbitrary copy holder:

| Evidence | Who can present it | Effect |
| --- | --- | --- |
| OIDC token with the caller binding as nonce | the holder's login, the IdP, the client operator | `Admitted` event to the bound caller |
| DKIM email or holder-signed POD bound to caller and choice (zkemail, zupass) | the sender and mail operator; the holder | `Admitted` receipt to the bound caller with the choice |
| Static documents and PODs without a holder key (aadhaar_secure_qr, philsys, zupass_pod) | anyone with a copy | record only: the core's nullifier |

## Residual risks

- A holder of a copy can act first (U1b) and use up the subject's one use;
  the fixed effect stops them redirecting anything.
- Static-document instances count one use per credential (one signed QR or
  POD), not per person: a new QR download is a new subject. One use per
  person is the uniqueness use case.
- Undated evidence never becomes stale: an old copy works as well as a new
  one.
- With an OIDC client binding, the client operator chooses the bound caller
  and choice.
- The nullifier omits the scheme and the issuer. That is sound with one
  terms per contract; a `gate_with_bound_terms` contract that accepts several
  issuers under one scope must make subjects issuer-unique.

## Tests

`common/src/tests.nr` covers the context-free rules and the predicates. The
TXE tests in `../testing/core_tests/src/attribute_gate.nr` cover a valid
gate, a second use, a false predicate, another caller's binding, stale
evidence, the bearer ceiling, undated evidence refused and accepted, a wrong
issuer, a choice from prover-set and holder-bound evidence, the requested
inclusion expiry, and `gate` and `gate_with_choice` with valid and wrong
terms at deployed keyless shells. TXE has one fixed caller per private
context, so an instance's "another caller" case presents the same
credential again or checks the signature against another caller's binding.

## Instances

<!-- use-case-instances:start -->
Each instance is a contract in `<scheme>/src/main.nr`, entrypoint `act(terms, evidence)` (zkemail, zupass: `act(terms, evidence, choice)`), package `<scheme>_attribute_gate`, tested by `scripts/test-use-cases.sh attribute-gating/<scheme>`. Its `src/test.nr` has the tests `valid`, `predicate_false_rejected`, `wrong_binding_rejected`, `stale_rejected`, `second_use_rejected`; [use-cases.json](../use-cases.json) records each exception and its reason. The category is the evidence category of [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).

| Instance | Category | Contract | Adapter | Residual risk and notes |
| --- | --- | --- | --- | --- |
| [aadhaar_secure_qr](aadhaar_secure_qr/src/main.nr) | 6 | `AadhaarSecureQrAttributeGate` | [`uc_adapter_aadhaar_secure_qr`](../adapters/aadhaar_secure_qr/src/lib.nr) | Record-only effect; one use per signed QR, not per person: a new download passes again. No authenticated UIDAI certificate is in the repository: the deployer must obtain and pin it, and pinning the published upstream test key accepts QRs made by anyone. UIDAI logs downloads and can link each nullifier to a person. The adapter derives the expiry from the anchor and pinned values only, so it reveals nothing about issuance; pinned QR ages above 13800 s are refused. Anchor at the latest block. |
| [entra](entra/src/main.nr) | 3 | `EntraAttributeGate` | [`uc_adapter_entra`](../adapters/entra/src/lib.nr) via `OidcAttribute` | The tenant is the issuing directory: B2B guests pass as well as members, so the gate shows no employment. `sub` is pairwise per application: one person with several accounts passes once per account. |
| [franceconnect](franceconnect/src/main.nr) | 3 | `FranceconnectAttributeGate` | [`uc_adapter_franceconnect`](../adapters/franceconnect/src/lib.nr) via `OidcAttribute` | Reports the signed `acr` rank (2 or 3), never the configured minimum; `eidas1` is outside the FranceConnect+ domain. Needs `FranceConnectAssuranceToken`: `FranceConnectIdToken` reports no attribute. |
| [govbr](govbr/src/main.nr) | 3 | `GovbrAttributeGate` | [`uc_adapter_govbr`](../adapters/govbr/src/lib.nr) via `OidcAttribute` | `sub` is the CPF: anyone can compute the gate nullifier of every CPF and learn which CPFs used this app, as with the gov.br login link. The level is what gov.br reports at login. Tokens live 60 s. |
| [philsys](philsys/src/main.nr) | 6 | `PhilsysAttributeGate` | [`uc_adapter_philsys`](../adapters/philsys/src/lib.nr) | Undated (`allow_undated`): an old copy works as well as a new one. Proves issuer authenticity only, not the presenter, active status or revocation; one use per QR, not per person. No authentic positive issuer vector exists: pinning a synthetic key accepts anyone's QRs. Legacy JSON QR only (not COSE ePhilID). The compiler reports an unresolved Brillig-coverage diagnostic in the upstream SHA-512 path. |
| [singpass](singpass/src/main.nr) | 3 | `SingpassAttributeGate` | [`uc_adapter_singpass`](../adapters/singpass/src/lib.nr) via `OidcAttribute` | The level is what Singpass reports for this login. `sub` is one Singpass account at this client, not one per person. |
| [university](university/src/main.nr) | 3 | `UniversityAttributeGate` | [`uc_adapter_university`](../adapters/university/src/lib.nr) via `OidcAttribute` | The affiliation is as asserted (CILogon may pass a cached value), not current enrolment. The prover picks which listed entry to present; entries over 128 bytes or signed lists over 256 bytes are refused. |
| [zkemail](zkemail/src/main.nr) | 3 | `ZkemailAttributeGate` | [`uc_adapter_zkemail`](../adapters/zkemail/src/lib.nr) | Domain-authorised mailbox control, not employment or identity: the mail operator can choose the caller and the choice. A reassigned mailbox keeps the same subject. The recipient and subject text are not constrained. |
| [zupass](zupass/src/main.nr) | 2 | `ZupassAttributeGate` | [`uc_adapter_zupass`](../adapters/zupass/src/lib.nr) | The nullifier subject is the ticket POD (`pod_id`), not the holder: one use per POD whatever the entry or choice. The pinned numeric entry must mean a nonnegative `int` (POD `int`, `cryptographic`, `boolean` and `date` hash alike). The holder's signed time says nothing about ticket expiry or revocation. |
| [zupass_pod](zupass_pod/src/main.nr) | 6 | `ZupassPodAttributeGate` | [`uc_adapter_zupass`](../adapters/zupass/src/lib.nr) | No holder signature: any copy holder can act first; record-only effect. Undated: revoked or expired tickets pass. The entry type is not proven (`int`, `cryptographic`, `boolean` and `date` hash alike): the issuer's schema must make the pinned entry an `int`. Values above 2^63 - 1 are refused. |
<!-- use-case-instances:end -->
