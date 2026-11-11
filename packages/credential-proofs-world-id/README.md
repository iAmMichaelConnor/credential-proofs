# credential-proofs-world-id

Experimental World ID 3 and 4 uniqueness policies and Groth16 codecs for Aztec
v6. Import strict encodings, context hashes (`signalBytes`,
`contextSignalHash`), version-specific policy checks and nullifier helpers from
the package root. Import `prepareWorldIdGroth16`, `worldIdPrivateArguments` and
the compression codecs from `/groth16`.

`checkClaim` is a policy check, not cryptographic verification; the Noir
Groth16 verifier checks the proof. The claim, signal encoding and trust
boundaries are specified in [docs/world-id.md](../../docs/world-id.md).

## The `groth16-verifier-hints` peer

`/groth16` needs `groth16-verifier-hints`, the hint SDK of
[groth16-verifier](https://github.com/iAmMichaelConnor/groth16-verifier)
(`packages/groth16-verifier-hints`). It is not on npm, so it is an optional peer
dependency: the package root works without it. Install it from a
groth16-verifier checkout at the tag this repository's Noir packages use
(v0.1.0), as a packed tarball:

```sh
npm ci                                          # from the repository root
./scripts/world-id/install-groth16-verifier-hints.sh     # clones the v0.1.0 tag
./scripts/world-id/install-groth16-verifier-hints.sh ../groth16-verifier   # or an existing checkout
```

The script installs without saving, so a later `npm ci` removes the peer again.

## Tests

No test creates a proof.

```sh
npm test -w credential-proofs-world-id                 # policies and encodings; no peer needed
npm run test:groth16 -w credential-proofs-world-id     # also the Groth16 codecs; needs the peer
node scripts/world-id/test-sdk-package.mjs      # packs both packages and imports them in a scratch consumer
```
