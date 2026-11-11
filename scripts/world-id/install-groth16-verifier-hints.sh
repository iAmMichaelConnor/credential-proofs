#!/usr/bin/env bash
# Install groth16-verifier-hints, the optional peer dependency of packages/credential-proofs-world-id,
# into the repository's npm workspace without saving it to package.json or the lockfile.
# The hints SDK is not on npm; it lives in groth16-verifier's packages/groth16-verifier-hints,
# which keeps its built dist/ in git. This packs it from a checkout and installs the
# tarball.
# Usage: ./scripts/world-id/install-groth16-verifier-hints.sh [groth16-verifier checkout]
# Without an argument it clones the groth16-verifier tag this repository's Noir
# dependencies use. Run `npm ci` first: a later `npm ci` removes the package again.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tag=v0.1.0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_dir="${1:-}"
if [ -z "$source_dir" ]; then
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" \
    https://github.com/iAmMichaelConnor/groth16-verifier "$tmp/groth16-verifier"
  source_dir="$tmp/groth16-verifier"
fi
hints="$(cd "$source_dir/packages/groth16-verifier-hints" && pwd)"
tarball="$(cd "$hints" && npm pack --ignore-scripts --silent --pack-destination "$tmp")"

cd "$root"
npm install --no-save --ignore-scripts --no-audit --no-fund "$tmp/$tarball"
node -e 'import("groth16-verifier-hints").then(m => { if (typeof m.prepareRuntimeHints68 !== "function") process.exit(1); })' \
  || { echo "groth16-verifier-hints installed but its API differs" >&2; exit 1; }
echo "Installed groth16-verifier-hints from $hints"
