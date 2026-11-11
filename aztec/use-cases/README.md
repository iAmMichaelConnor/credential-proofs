> **Experimental software. Unaudited. May contain bugs.**

# Use-case contract examples

These examples apply the credential libraries of [`noir/`](../../noir) to six
application patterns. Generic cores enforce shared rules; adapters verify evidence and
report its authority, binding and time properties; instance contracts commit
to a policy and choose the effect. Each category README states its rules and
residual risks once, and its instance table adds what each instance changes
(the same notes head the instance's `src/main.nr`).

Account examples use a custom entrypoint ABI, external fee payment and
immutable policies; they supply no wallet wrapper, key rotation or recovery.
Login links return an identity and consume its scoped nullifier. Some gates
and events only consume a nullifier. Settlement delivers a receipt to a fixed
beneficiary, not tokens. Uniqueness has a tested generic core and no
instance contract.

The [architecture reference](ARCHITECTURE.md) covers the trust labels, the
rules and risks shared by every category, the layout, the generator, testing
and instance authoring.

<!-- use-case-grid:start -->
Generated from [use-cases.json](use-cases.json) by
[scripts/generate.py](scripts/generate.py). Each category lists its implemented instances.

| Use case | Instances | Statement |
| --- | ---: | --- |
| [account-authorisation](account-authorisation/README.md) | 21 | The account owner approved this exact payload. |
| [login-link](login-link/README.md) | 19 | A challenge-bound login, or explicitly accepted bearer evidence, links an identity. |
| [attribute-gating](attribute-gating/README.md) | 10 | A credential with attribute A was presented; a fixed effect happens. |
| [uniqueness](uniqueness/README.md) | 0 | This person has not done this in this app before; a fixed effect happens. |
| [payment-settlement](payment-settlement/README.md) | 3 | A payment matching this order happened; the order's fixed effect happens once. |
| [event-proof](event-proof/README.md) | 2 | This external event happened; a fixed effect happens once per event. |
<!-- use-case-grid:end -->
