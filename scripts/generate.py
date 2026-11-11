#!/usr/bin/env python3
"""Run every generator; with --check, write nothing and fail on drift.

- scripts/fixtures/generate.py: fixtures, known-answer tests and generated Noir
  test modules (needs Node.js, `npm ci && npm run build` at the root, and
  $GROTH16_VERIFIER, a groth16-verifier v0.1.0 checkout with `npm ci` in
  packages/groth16-verifier-hints);
- scripts/world-id/import_world_id_fixtures.py: the World ID vectors imported
  from fixtures/world-id/upstream;
- aztec/use-cases/scripts/generate.py: the generated parts of the use-case
  contracts;
- aztec/use-cases/scripts/check_fixtures.py: the use-case fixtures (needs
  `npm ci` in aztec/use-cases).

Generated Noir is formatted with $NARGO, else nargo on PATH; the use-case
generators need nargo 1.0.0-rc.3, the version Aztec 6.0.0 ships.
"""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATORS = [
    ["scripts/fixtures/generate.py"],
    ["scripts/world-id/import_world_id_fixtures.py"],
    ["aztec/use-cases/scripts/generate.py"],
    ["aztec/use-cases/scripts/check_fixtures.py", "--require"],
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; fail if a generated file is stale")
    args = parser.parse_args()
    failed = []
    for generator, *options in GENERATORS:
        command = [sys.executable, generator, *options] + (["--check"] if args.check else [])
        print(f"$ {' '.join(command[1:])}", flush=True)
        if subprocess.run(command, cwd=ROOT).returncode != 0:
            failed.append(generator)
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
