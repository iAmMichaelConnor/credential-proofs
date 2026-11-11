# Contributing

Thank you for your interest in contributing! This guide covers the
[layout](#layout), [setup](#setup), [tests](#tests), [benchmarks](#benchmarks),
[generated files](#generated-files), [vendored code](#vendored-code),
[releases](#releases) and how this repository [differs from the
noir-library-starter
template](#differences-from-the-noir-library-starter-template). Keep pull
requests focused, and open an issue first for anything substantial. Breaking
changes must update the README or the documentation. Run every command below
from the repository root.

## Layout

```
noir/<package>                 Nargo workspace of the libraries, one package per directory
noir/<package>/src/benchmarks.nr        #[export] benchmark functions (complete relations)
noir/<package>/src/known_answer_tests.nr generated end-to-end tests on fixture material
noir/<package>_slow_tests      sibling crates of end-to-end tests that need their own nightly handling
vendor/noir-ed25519            modified copy of noir-ed25519 (see Vendored code)
aztec/                         Nargo workspace of the Aztec example contracts (.aztecrc, noirfmt.toml)
aztec/world-id-v3, -v4         World ID gate contracts and their TXE tests
aztec/use-cases                use-case cores, adapters, generated instance contracts and their TXE tests
fixtures/                      credential material (manifests in fixtures/material/<scheme>) and World ID proofs
packages/credential-proofs-inputs     host input preparation (private npm workspace package)
packages/credential-proofs-world-id   World ID requests, policy and Groth16 codecs (private npm workspace package)
packages/credential-proofs-capture    capture pages where users perform their own login or assertion
scripts/                       test, selection and benchmark scripts; generators (scripts/fixtures, scripts/world-id)
docs/                          security model and per-scheme material
```

## Setup

- Noir: install with [noirup](https://github.com/noir-lang/noirup), e.g.
  `noirup -v 1.0.0`. Either version CI tests works (see the README).
- Node.js 22 and `npm ci` at the repository root, for the host packages and the
  fixture generators; `npm ci` in `aztec/use-cases` for the use-case fixture
  generators. Python 3 with `pip install -r scripts/fixtures/requirements.txt`
  (`cryptography`) for the X.509 fixture generators; every other Python script
  uses the standard library only.
- bb, only for benchmarks:
  `curl -L https://bbup.aztec.network | bash && ~/.bb/bbup -v 6.0.0`.
- The Aztec toolchain, only for `aztec/`:
  `curl -fsSL https://install.aztec-labs.com | VERSION=6.0.0 bash`.
- groth16-verifier: `anon_aadhaar_v2_auth` and `world_id_uniqueness` depend on
  `https://github.com/iAmMichaelConnor/groth16-verifier` at tag `v0.1.0`, and
  the Anon Aadhaar fixtures and the World ID SDK use its hint SDK. Until that
  tag is published nargo cannot fetch it, so put a checkout of the intended
  v0.1.0 contents where nargo looks for the tag, and name the same checkout to
  the scripts:

  ```bash
  mkdir -p ~/nargo/github.com/iAmMichaelConnor/groth16-verifier
  rsync -a --delete --exclude .git --exclude node_modules --exclude target \
    ../groth16-verifier/ ~/nargo/github.com/iAmMichaelConnor/groth16-verifier/v0.1.0/
  ./scripts/world-id/install-groth16-verifier-hints.sh ../groth16-verifier
  (cd ../groth16-verifier/packages/groth16-verifier-hints && npm ci)
  export GROTH16_VERIFIER=../groth16-verifier
  ```

  Nargo uses a directory that exists under `~/nargo` as it is, so refresh that
  copy whenever the checkout changes. Once the tag is published, delete the copy:
  nargo then fetches the tag like any other dependency.
- Dependencies tracked at `main`: keccak256 and noir-edwards are `tag = "main"`
  dependencies (versions in the README's compatibility section), because the
  fixes these packages need are not in any upstream release. An upstream push
  can therefore change their behaviour; the nightly workflow runs every test
  against the current `main` of both.

## Tests

`nargo test` proves nothing: it compiles each test to a circuit and executes it.
For a multi-million-gate relation (a signed JWT, an RSA-4096 key, a Groth16
proof) constrained execution takes minutes and gigabytes, while unconstrained
execution of the same test code (`--force-brillig --inliner-aggressiveness 0`)
takes seconds and passes the same tests. So every package runs unconstrained on
every pull request and constrained nightly, with the thread count
[`scripts/nightly-threads.txt`](scripts/nightly-threads.txt) gives it (default
4) to fit a 16 GB runner; [`scripts/run-tests.sh`](scripts/run-tests.sh) applies
both. A `*_slow_tests` crate is a sibling crate holding tests that need their
own handling in the nightly constrained run (memory or time) or that only make
sense constrained; it also runs per pull request when its fast mode takes under
about 2 minutes. Every `*_slow_tests` crate here runs per pull request.

**Per pull request** CI tests only what the change can affect.
[`scripts/changed-packages.sh <base-ref>`](scripts/changed-packages.sh) maps the
changed files to the affected sets through the real dependency graph: a file in
a Nargo package selects that package and every package that depends on it
transitively (`vendor/` and `*_slow_tests` crates included); a generator or a
generator input selects what consumes its output; `packages/` selects every
use-case instance and every package whose fixtures the host code generates;
documentation (the top-level `*.md` files, `LICENSE`, `NOTICE` and `docs/`)
selects nothing; and the rest of `scripts/`, `.github/`, the toolchain files,
the workspace and npm manifests and any file no rule claims select everything.
Every change except documentation runs the host job. The script's header states
every rule in order; `./scripts/changed-packages.sh --self-test` checks each
rule against the repository's own dependency graph and listings in about a
second. A push to `main` tests everything. The jobs of
[`test.yml`](.github/workflows/test.yml):

| Job | Runs | When |
| --- | --- | --- |
| `format` | `nargo fmt --check` of both workspaces, the selection self-test, `scripts/generate.py --check` | always |
| `changes` | `scripts/changed-packages.sh` | always |
| `test` | each affected package on Noir 1.0.0-rc.3 and 1.0.0, unconstrained, `--test-threads 4` | affected packages |
| `host` | host package tests, fixture manifests, World ID gate fixture checks, the generators' unit tests | every change except documentation |
| `examples` | `check` (`aztec-nargo check` of the affected aztec/ packages, four at a time), `world-id`, `cores`, `adapters`, the affected use-case instances in groups of six | affected examples |
| `tests-end` | fails if a job failed or was cancelled, or if the selection asked for a job that was skipped | always |

With every package selected (a push to `main`), the `test` job runs 82 jobs: 41
packages on two toolchains.

Expected wall time of a pull request on hosted runners, jobs in parallel: a
documentation-only change runs `format` and `changes` (about 5 minutes); a leaf
package such as `kakao` adds its package jobs, the host job, the type-check of
three aztec/ packages, the adapters and its two instances (about 10 minutes); a
shared dependency such as `oidc` or `rsa_signature` selects 16 to 24 packages,
about 45 aztec/ packages to type-check and 30 to 40 instances in 7 to 11 groups
(about 15 minutes, set by the example groups). No package job takes more than
about two minutes; the longest examples job is the World ID group (about 6
minutes).

On a pull request the benchmark workflow measures the affected benchmark
packages only, and its gate and Brillig diffs cover those packages. Every
package is measured only when the workflow is started by hand.

**Nightly** [`nightly-canary.yml`](.github/workflows/nightly-canary.yml) runs
everything, whatever changed: every package unconstrained on Noir nightly; every
package constrained on Noir 1.0.0, one job per package with a 120-minute timeout
(the longest measured run is 44 minutes, and `wechatpay` is unmeasured); the
host job; and every examples group (the type-check of every aztec/ package, the
World ID gates, the cores, the adapters and every use-case instance). It is the
backstop for a selection miss and for the two dependencies tracked at `main`.
The `base64url` job also runs `scripts/base64url-hint-disabled-check.py` (about
2 seconds), which shows that the constraints of `base64url` reject non-URL-safe
input without the Brillig hint. A separate `compile-examples` job compiles every
aztec/ package to a circuit; it takes about 390 CPU-minutes, so it runs only
when the workflow is started by hand (`workflow_dispatch`).

Locally:

```bash
./scripts/run-tests.sh --jobs 16 --test-threads 8                      # every package, unconstrained
./scripts/run-tests.sh --package oidc                                  # one package
./scripts/run-tests.sh --nightly --package govbr_slow_tests            # one package, constrained
nargo --program-dir noir fmt --check && nargo --program-dir aztec fmt --check
TXE_PORT=8081 ./scripts/test-world-id.sh                               # World ID gates (Aztec toolchain)
TXE_PORT=8101 aztec/use-cases/scripts/test-use-cases.sh --jobs 24 all  # selectors: cores, adapters, <use case>[/<scheme>]
TXE_PORT=8081 ./scripts/test-world-id.sh --unconstrained-contracts     # also the World ID deploy tests
TXE_PORT=8101 aztec/use-cases/scripts/test-use-cases.sh --unconstrained-contracts account-authorisation/ethereum_secret_key
(cd aztec && aztec-nargo check --workspace)                            # type-check every example
npm ci && npm test -w credential-proofs-inputs && npm run test:material
npm test -w credential-proofs-world-id
./scripts/world-id/install-groth16-verifier-hints.sh && npm run test:groth16 -w credential-proofs-world-id
python3 -m unittest discover -s scripts/fixtures/tests -p 'test_*.py'
python3 -m unittest discover -s scripts/world-id/tests -p 'test_*.py'
python3 -m unittest discover -s aztec/use-cases/scripts/tests
```

`run-tests.sh` takes `--test-threads N` (default: the number of cores; CI passes
4) and `--jobs N` (packages at once, default 1); memory grows with both. The
figures below were measured locally with Noir 1.0.0 and Aztec 6.0.0.
Unconstrained, all 41 packages at once (`--jobs 16 --test-threads 8`, a local
run): 34 s wall. The longest (every other package took under 15 s and 2.6 GB):

| Package | Tests | Local run, unconstrained, 8 threads: wall time, peak RSS |
| --- | ---: | --- |
| `ed25519_auth_slow_tests` | 16 | 30 s, 5.1 GB |
| `anon_aadhaar_v2_auth_slow_tests` | 8 | 27 s, 2.7 GB |
| `ed25519_auth` | 7 | 23 s, 1.8 GB |
| `philsys_auth_slow_tests` | 1 | 22 s, 0.8 GB |
| `ethereum_auth` | 28 | 21 s, 1.7 GB |
| `philsys_auth` | 9 | 21 s, 1.8 GB |
| `oidc` | 160 | 14 s, 2.0 GB |

Constrained, one package at a time; a row "with its slow tests" includes the
tests of its `*_slow_tests` crate, so it is an upper bound for the package
alone. The nightly column is the thread count CI uses
(`scripts/nightly-threads.txt`):

| Package | Tests | Nightly threads | Local run: threads, wall time, peak RSS |
| --- | ---: | ---: | --- |
| `university_auth` (with its slow tests) | 23 | 4 (slow tests 2) | 4: 39 min, 24 GB |
| `govbr` (with its slow tests) | 15 | 4 (slow tests 1) | 4: 34 min, 31 GB |
| `franceconnect` (with its slow tests) | 20 | 4 (slow tests 2) | 4: 19 min, 14 GB |
| `entra` (with its slow tests) | 8 | 4 (slow tests 1) | 4: 14 min, 28 GB |
| `entra_slow_tests` | 6 | 1 | 1: 44 min, 9.2 GB |
| `linkedin` | 15 | 4 | 4: 16 min, 7.6 GB |
| `oidc` | 160 | 4 | 4: 12 min, 8.4 GB |
| `singpass_auth` | 9 | 4 | 4: 12 min, 6.5 GB |
| `anon_aadhaar_v2_auth_slow_tests` | 8 | 1 | 4: 12 min, 31 GB; 6.5 min and 7.8 GB per test |
| `jpki_auth` | 6 | 4 | 4: 7 min 52 s, 7.7 GB |
| `line` | 10 | 4 | 4: 4 min 50 s, 8.7 GB |
| `telegram` | 7 | 4 | 8: 3 min 35 s, 7.2 GB |
| `philsys_auth` | 9 | 4 | 8: 2 min 33 s, 5.6 GB |
| `ed25519_auth` | 7 | 4 | 8: 1 min 58 s, 4.1 GB |
| `ethereum_auth` | 28 | 4 | 8: 1 min 41 s, 4.2 GB |

### Example contracts

The contracts under `aztec/` are examples: by default only the small keyless
shell contract `uc_terms_shell` is compiled and deployed; no example contract is
(outside the hand-started `compile-examples` job). `aztec-nargo check`
type-checks them (about 25 s per package; the whole workspace takes 25 minutes
on one core, a minute with 48 packages at once), and their logic runs in TXE
tests: the use-case instances through each instance's core at the keyless
`uc_terms_shell` contract (`aztec compile` and `bb aztec_process`, about 17 s,
once per run); the World ID gates in `TestEnvironment` contexts at the gate's
address, through the plain functions that the gates' entry points call, on
storage written by the constructor's body. TXE runs circuits and state but
makes no proofs.

A handful of deploy tests cover what only a deployed contract shows. They run
with `--unconstrained-contracts` (`scripts/test-world-id.sh` and
`aztec/use-cases/scripts/test-use-cases.sh`), which compiles the contracts they
deploy unconstrained (`aztec-nargo compile --force-brillig
--inliner-aggressiveness 0`, then `bb aztec_process`; about 12 s and 0.5 GB per
contract), which TXE runs the same way and which is faster. Those artifacts are
for tests only and must never be deployed, and a contract's address differs
from that of a constrained build, so anything bound to an address must be
produced for the artifact under test.

- [`aztec/world-id-deploy-tests`](aztec/world-id-deploy-tests) deploys each
  World ID gate with its initializer and reads back every stored value, so a
  `constructor` that swaps two arguments of the same type (World ID 3's
  `inner_key`, `root` and `external_nullifier`) fails; a second constructor
  call with other arguments fails the initialisation check that
  `#[initializer]` adds; and a claim at a gate deployed without its initializer
  fails.
- [`aztec/use-cases/testing/dispatch_target`](aztec/use-cases/testing/dispatch_target)
  (with the selector `account-authorisation/ethereum_secret_key`) deploys the
  `ethereum_secret_key` account and calls its `entrypoint` through the ABI with
  a payload whose one call runs on a deployed target: the call runs with the
  account as `msg_sender`, a target expecting another sender rejects it,
  another key fails before anything is dispatched, and a replay of the
  transaction nonce fails. The scheme signs nothing, so its credential is not
  bound to the account's address.

Not covered: the ABI boundary and compiled bytecode of the other example
contracts; the addresses derived from constrained verification keys; a
contract calling another deployed contract, except the `ethereum_secret_key`
account's dispatch; the argument forwarding in the World ID gates' `claim` (one
call to the tested library method; a swap of `beneficiary` and `nonce` would
type-check), because the saved Groth16 proofs bind the fixed address of the
context tests, which no deployment can have (a deployed address derives from
the class id, salt, initialisation hash and keys), so no claim at a deployed
gate passes the signal binding, whichever way the two are passed; and the
initialisation check that `#[initializer]` adds to `claim` on its own, because
at a gate deployed without its initializer the claim's first storage read fails
before TXE checks that check's nullifier read request, and only the
constructor writes storage.

| Suite | Tests | Wall time |
| --- | ---: | --- |
| `test-use-cases.sh --jobs 24 --test-threads 8 all` (90 packages) | 1,239 | 8 min 1 s |
| `test-world-id.sh --test-threads 16` | 39 | 5 min 22 s |
| `test-use-cases.sh --jobs 4 --test-threads 4 --unconstrained-contracts account-authorisation/ethereum_secret_key`, four cores | 10 + 4 | 1 min 19 s: 12 s to compile both contracts, 51 to 71 s and 1.4 GB for the deploy tests |
| `test-world-id.sh --test-threads 4 --unconstrained-contracts`, four cores | 39 + 6 | 4 min 59 s: 12 s to compile both gates, 30 s and 1.6 GB for the deploy tests alone |

Each World ID gate has two constrained tests that run the whole claim with its
Groth16 verification (4 to 5 minutes and 2.5 GB each; unconstrained, the
verifier takes over an hour); the rest run the same claim composition with a
stand-in for the verification step, unconstrained. At
`--test-threads 4` the three World ID packages together peak at about 12.6 GB.

`scripts/txe-server.mjs` starts the Aztec CLI's TXE with a
one-hour HTTP keep-alive instead of Node's 5 s default: TXE disposes a test's
session when its socket closes, so a test with more than 5 s of unconstrained
work between two oracle calls (the PhilSys QR, secp256k1 key derivation) fails
under load with the default server. Both TXE test scripts use it.

### Exceptions

- Two tests are bare `#[test(should_fail)]`, because the assertion that rejects
  their input has no message upstream; each carries a `// Bare:` comment naming
  it: `ed25519_auth` `reject_point_offcurve_hint` (noir-edwards-bignum
  v0.1.0-alpha.4 `src/lib.nr:166`) and `zupass` `invalid_point` (noir-edwards
  `main` `src/lib.nr:165`). Every other rejection test, the use-case TXE tests
  included, names its failure with `should_fail_with`; the use-case generator's
  lint checks them.
- The `rsa` dependency of `rsa_signature` is pinned to the tag
  `v0.12.1-assert-messages.1` of iAmMichaelConnor/noir_rsa, which is
  zkpassport/noir_rsa v0.12.1 plus the assert messages proposed upstream in
  zkpassport/noir_rsa#22 to #24. It returns to an upstream release tag once one
  carries them.
- Two rejection inputs of the end-to-end vectors are not tests, because the
  constraint that rejects them has no message: gov.br `RejectWrongKey` and JPKI
  `BadRedc` (a noir-bignum hint check). The generated modules list them with
  their reasons.
- Not run to completion locally: the `wechatpay` constrained suite (53 tests,
  about 3 minutes each at two threads, so over an hour); it runs nightly.

## Benchmarks

Each library package with an end-to-end relation has a `benchmarks.nr` module of
`#[export]` functions, one per relation, with the shapes of its known-answer
tests; names are unique across the workspace.
`./scripts/build-gates-report.sh --jobs N [package...]` exports and measures
them N at a time (the largest exports need about 7 GB and up to 16 minutes
each). On a pull request the benchmark workflow measures the affected benchmark
packages only. Started by hand on `main`, it measures every package and records
history on the `gh-pages` branch, which must exist before the first workflow
run; no push starts it, because that run takes hours. Its timeout is 240
minutes: 28 benchmark packages exported one at a time, the largest taking up to
16 minutes each, exceed the default 60.

## Generated files

Generated files are never edited by hand. Each family has one generator, which
rewrites its outputs or, with `--check`, writes nothing and fails if a committed
file is stale. `python3 scripts/generate.py [--check]` runs the first four (CI's
`format` job); it formats Noir with `$NARGO`, else `nargo` on `PATH`, which must
be 1.0.0-rc.3 for the use-case generators.

| Generator | Writes | From |
| --- | --- | --- |
| `scripts/fixtures/generate.py` | `fixtures/` (synthetic material, manifest hashes), every `known_answer_tests.nr`, the generated test modules (zkEmail headers, passkey browser vectors, WeChat Pay scanner, Aadhaar vectors, RSA API tests, Ed25519 RFC and edge vectors, X.509 vectors, PhilSys, Singpass and university fixtures, LINE fixture, Zupass holder fixtures) | fixture material and test keys in `fixtures/`, through the generators in `scripts/fixtures/` |
| `scripts/world-id/import_world_id_fixtures.py` | `fixtures/world-id/provenance.json` and the imported vectors | `fixtures/world-id/upstream` |
| `aztec/use-cases/scripts/generate.py` | instance `Nargo.toml` and `src/main.nr`, category README tables, the use-case members of `aztec/Nargo.toml` | `aztec/use-cases/use-cases.json` |
| `aztec/use-cases/scripts/check_fixtures.py` | each instance's `src/fixture.nr` and `fixtures/manifest.json` | the fixture generators in `aztec/use-cases/scripts/fixtures/generators` |
| `scripts/world-id/world_id_foundation.mjs`, `world_id4_foundation.mjs` | `aztec/world-id-v{3,4}/tests/src/fixture.nr` | the saved proofs in `fixtures/world-id` |

`scripts/fixtures/generate.py` runs its generators in a scratch copy: the
fixture generators write each known-answer case's inputs to `target/kat/`,
`scripts/fixtures/kat.py` turns them into Noir literals (types from the ABI of
the package's benchmark function) and checks every rejection reason against
the expected message. Signing is deterministic (RSA PKCS#1 v1.5, Ed25519,
ES256 with RFC 6979, fixed clocks), so `--check` is exact. It needs
`npm ci && npm run build` at the repository root and `GROTH16_VERIFIER` (see
[Setup](#setup)): the Anon Aadhaar inputs are prepared with the hint SDK.

The Anon Aadhaar proof (`fixtures/data/anon-aadhaar-v2`) is upstream material
and is kept as is; only its circuit inputs are derived.
`noir/anon_aadhaar_v2_auth/src/application_key.nr` (after `nargo fmt`) and
`fixtures/anon-aadhaar/key/` come from groth16-verifier's key generator, run in
`packages/groth16-verifier-hints/python` of a v0.1.0 checkout:

```bash
python3 -m groth16.generate --vk <this repository>/fixtures/material/anon_aadhaar/provider-public/vkey.json \
  --out <new directory> --name anon_aadhaar_v2 --provider-name AnonAadhaarV2Key \
  --dependency-alias groth16 --mode private --key-policy fixed
```

`fixtures/material/<scheme>/manifest.json` records each file's origin, trust
role and sha256; `npm run test:material` validates them.

### World ID gate fixtures

The World ID gate tests replay saved Groth16 proofs
(`fixtures/world-id/aztec-foundation.json` for World ID 3,
`aztec-v4-foundation.json` for World ID 4). Each proof's signal binds the chain
id and version (1 in TXE), a fixed gate address (`ADDRESS` in each generator),
the action, beneficiary 13 and nonce 17. The tests run the gate's claim in a TXE
private context at that address, so changes to the contracts, their dependencies
or the compiler do not invalidate the proofs. `world_id*_foundation.mjs --check`
(in the `host` job) fails if `fixture.nr` is stale or a saved proof is not bound
to the generator's context; it needs Node.js, the SDK built with its Groth16
peer and nargo 1.0.0-rc.3. A new proof is needed only when the bound context,
the key or the statement changes:

1. Build: `npm ci`, `./scripts/world-id/install-groth16-verifier-hints.sh`
   (installs the groth16-verifier hint SDK, not on npm, without saving it) and
   `npm run build -w credential-proofs-world-id`.
2. In a scratch directory outside the repository, install the provers. snarkjs
   is GPL-3.0, so it is not a dependency of this repository:
   `npm install snarkjs@0.7.5 @semaphore-protocol/identity@3.15.2 @semaphore-protocol/group@3.15.2`.
3. Put the proving assets in that directory: `semaphore.wasm` and
   `semaphore.zkey` from https://www.trusted-setup-pse.org/semaphore/16/, and
   `OPRFNullifierProof.wasm` and `oprfnullifierproof_final.zkey` from the
   world-id-protocol OPRFNullifierProof ceremony (trusted-setup commit
   189abeafd2b9d7ec6729172990c8818a2717a628). The scripts check their sha256.
4. Run
   `node scripts/world-id/world_id_foundation.mjs --foundation-proof --work-dir <dir>`
   and
   `node scripts/world-id/world_id4_foundation.mjs --foundation-proof --work-dir <dir>`.
   Each takes seconds, rewrites the foundation JSON and `fixture.nr`, and checks
   the new proof natively.
5. Run `./scripts/test-world-id.sh`.

## Vendored code

`vendor/noir-ed25519` is a modified copy of willemolding/noir-ed25519 (see
[NOTICE](NOTICE)): the strict verifier depends on changes that the upstream
release does not have. It is maintained here, so there is no rebuild script.

## Releases

Pull request titles follow [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/), which drive the
changelog and version numbers:

```
<type>[optional scope]: <description>
```

- `feat:` new functionality (appears in the changelog);
- `fix:` bug fixes (appears in the changelog);
- `chore:` everything else (omitted from the changelog unless breaking).

Mark a breaking change with `!` after the type or scope, e.g.
`feat(oidc)!: Return the verified claims`. Use the package name as the scope
when a change touches one package.

[Release Please](https://github.com/googleapis/release-please) runs on every
push to `main`. It opens or updates a release pull request with the next version
and the changelog; merging that pull request tags the release. All packages
share one version and one tag. The first release is v0.1.0.

The release workflow uses the default `GITHUB_TOKEN`, and pull requests opened
with it do not trigger CI; to run the checks on release pull requests, replace
it in `release.yml` with a personal access token stored as a repository secret.

### Publishing checklist

Before the first release:

- create an empty `gh-pages` branch, where the benchmark workflow records
  history;
- enable private vulnerability reporting in the repository's security settings,
  for the README's reporting link;
- make groth16-verifier public and tag it `v0.1.0` first: the Groth16 packages,
  the format job and the World ID tests fetch that tag.

## Differences from the noir-library-starter template

- **Two workspaces, libraries under `noir/`.** The repository publishes about
  thirty libraries, so consumers add a `directory` to the git dependency. The
  Aztec examples need the Aztec toolchain, which pins its own nargo, so they
  form a second workspace in `aztec/`. Nargo resolves a package to the outermost
  workspace above it, so neither workspace can sit at the repository root:
  commands take `--program-dir noir`.
- **Two Noir versions per pull request.** The template tests every Noir release
  from the minimum supported version, and nightly, on each pull request. This
  repository tests the two ends, 1.0.0-rc.3 (the minimum, which Aztec 6.0.0
  ships) and 1.0.0 (the latest release), per pull request, and Noir nightly in
  the nightly workflow.
- **Unconstrained per pull request, constrained nightly.** A constrained test of
  a multi-million-gate relation takes minutes and gigabytes; the same test under
  `--force-brillig --inliner-aggressiveness 0` takes seconds.
  `scripts/run-tests.sh` runs both, with the nightly thread counts of
  `scripts/nightly-threads.txt`.
- **`*_slow_tests` crates.** End-to-end tests whose constrained runs take
  minutes each or need fewer threads sit in sibling crates, so that the nightly
  job of the rest of the package stays short and keeps four threads.
- **Affected-only CI.** About forty packages, a hundred example packages and the
  host code would take hours per pull request, so `scripts/changed-packages.sh`
  selects the tests, examples and benchmarks a change can affect; `main` runs
  every test and example, and the nightly workflow runs everything whatever
  changed. The full benchmark run is started by hand.
- **Extra CI jobs.** `changes` computes the selection; `host` runs the host
  packages', fixtures' and generators' tests; `examples` type-checks the Aztec
  examples and runs their TXE tests without compiling them.
- **One compiled contract in the example tests.** The template has no Aztec
  contracts. Here only the small keyless shell contract `uc_terms_shell` is
  compiled and deployed by default; no example contract is: each use-case test
  runs its instance's core in a private context at a deployed shell, so a test
  needs neither the compile time nor the memory of a full contract.
- **Example contracts compiled unconstrained for the deploy tests.**
  `--unconstrained-contracts` compiles the World ID gates, the
  `ethereum_secret_key` account and its test target with `--force-brillig`,
  which TXE runs the same way, so that the deploy tests take about a minute
  instead of a constrained compile per contract; the artifacts are test-only. The examples'
  formatting uses Aztec.nr's settings (`aztec/noirfmt.toml`); the libraries use
  `nargo fmt` defaults. The nightly canary covers the libraries only: Aztec.nr
  supports one nargo version per release.
- **No oracle server or differential tests.** The reference values are fixed
  vectors and known-answer tests generated into Noir from fixture material.
- **Generated tests need Node.js.** The format job installs Node.js, the host
  packages and a groth16-verifier checkout (its hint SDK prepares the Anon
  Aadhaar inputs), and runs `scripts/generate.py --check`. The JWT, X.509, POD
  and payment encoders have no standard-library Python equivalent.
- **Host packages.** `packages/` holds the TypeScript input preparation, the
  World ID SDK and the capture pages: without them a user cannot produce the
  circuit inputs.
- **Vendored Ed25519,** described under [Vendored code](#vendored-code).
- **Known exceptions to named failures,** listed under
  [Exceptions](#exceptions).
- **bb is installed by version.** `bbup -nv` cannot resolve Noir 1.0.0 (no entry
  in bbup's version map), so the benchmark workflow names bb 6.0.0 directly and
  measures with Noir 1.0.0 rather than the minimum version.
- **Release Please starts at 0.1.0** (`initial-version`), not at the template's
  0.0.0.
- **Workflows trigger on `main`**, not `master`, and third-party actions are
  pinned by commit.
