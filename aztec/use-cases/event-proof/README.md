> **Experimental software. Unaudited. May contain bugs.**

# Event proof (U5)

Statement: "this external event happened; a fixed effect happens once per
event". Examples: an email from domain D with tag T was received, an
attestor observed a web fact.

Core crate: [`uc_event_proof`](common/src/lib.nr) (`EventEvidence`, `Event`,
`EventTerms { accepted, kind, match_subject, subject, match_data, data,
max_age, scope }`, `on_event`). The instances' HAND-WRITTEN effect regions
are empty: the event nullifier is the effect, and a deployment adds its
fixed effect there.

## Rules

1. Trust accepted (source, issuer and, for evidence that carries an
   anchor, its kind, pinned value and minimum finality).
2. `kind` equals the terms. With `match_subject` or `match_data`, the subject
   or data hash also equals the terms.
3. Freshness: `occurred_at` at most `max_age` before the anchor block, and
   inclusion by `occurred_at + max_age` (`0xffffffffffffffff` accepts any
   age; the deadline then saturates).
4. One effect per event: nullifier `Poseidon2(MIKE_UC_EVENT_V1, scope,
   SCHEME, event_id)`. The adapter defines `event_id` as the evidence's own
   identity (below).

`SCHEME` enters the terms commitment and the nullifier: zkemail 8 and
twitter_reclaim 9 (the account ids; payment adapters use 61 to 63). Each
adapter's unit test checks its constant.

## Residual risks

- The source is trusted to report only real events: the mail domain for
  DKIM, the attestor for Reclaim.
- Event evidence names no holder, so event adapters never set
  `ALSO_COPY_HOLDER`: `refuse_also: ALSO_COPY_HOLDER` refuses nothing, and
  the bearer ceiling never applies; terms must not rely on either. Anyone
  with a copy can trigger the fixed effect first.
- One effect per evidence identity, which each adapter defines (DKIM signed
  header, Reclaim claim identifier), not per real-world fact.
- A contract that accepts one event through two adapters gets two
  nullifiers for it; such a consumer restricts the scheme or defines a shared
  event identity.

## Tests

`common/src/tests.nr` covers the context-free rules. The TXE tests in
`../testing/core_tests/src/event.nr` cover a valid event, a replay, the next
log of the same transaction, a wrong kind, subject and data, matching data,
a stale event, an untrusted anchor, insufficient finality, any age under the
maximum `max_age`, the requested inclusion expiry, and `on_event` with valid
and wrong terms at deployed keyless shells.

## Instances

<!-- use-case-instances:start -->
Each instance is a contract in `<scheme>/src/main.nr`, entrypoint `on_event(terms, evidence)`, package `<scheme>_event_proof`, tested by `scripts/test-use-cases.sh event-proof/<scheme>`. Its `src/test.nr` has the tests `valid`, `wrong_kind_rejected`, `stale_rejected`; [use-cases.json](../use-cases.json) records each exception and its reason. The category is the evidence category of [ARCHITECTURE.md](../ARCHITECTURE.md#evidence-and-authority).

| Instance | Category | Contract | Adapter | Residual risk and notes |
| --- | --- | --- | --- | --- |
| [twitter_reclaim](twitter_reclaim/src/main.nr) | 4 | `TwitterReclaimEventProof` | [`uc_adapter_twitter_reclaim`](../adapters/twitter_reclaim/src/lib.nr) | One effect per claim, not per fact: a claim with a new requester-chosen context is a new event unless the terms pin the context with `match_data`. The official X provider profile cannot produce usable proofs today. |
| [zkemail](zkemail/src/main.nr) | 3 | `ZkemailEventProof` | [`uc_adapter_zkemail`](../adapters/zkemail/src/lib.nr) | DKIM shows the domain signed headers addressed to the recipient, not delivery. The kind pins the whole sender mailbox, which keeps other users of the domain out only if its mail service stops them sending as other mailboxes. The body is not read unless `match_data` pins it. |
<!-- use-case-instances:end -->
