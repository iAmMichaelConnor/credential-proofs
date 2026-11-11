#!/usr/bin/env bash
# Export the #[export] benchmark functions of noir/ packages and write the gate
# report (gates_report.json, benchmark-opcodes.json, benchmark-circuit.json).
#
#   ./scripts/build-gates-report.sh [--jobs N] [package...]
#
# Without packages, every package with a src/benchmarks.nr is exported. Exports
# and `bb gates` run N at a time (default: the number of cores); each export
# compiles its package single-threaded, so concurrency is what makes this fast.
set -eu

BACKEND=${BACKEND:-bb}
NARGO=${NARGO:-nargo}
jobs=$(nproc)
packages=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs) jobs="$2"; shift 2 ;;
        --jobs=*) jobs="${1#--jobs=}"; shift ;;
        *) packages+=("$1"); shift ;;
    esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
if [[ ${#packages[@]} -eq 0 ]]; then
    for benchmarks in noir/*/src/benchmarks.nr; do
        packages+=("$(basename "$(dirname "$(dirname "$benchmarks")")")")
    done
fi

# The Nargo workspace that holds the packages.
workspace=noir
artifacts_path="$workspace/export"
rm -rf "$artifacts_path"
mkdir -p "$artifacts_path"
printf '%s\n' "${packages[@]}" |
    xargs -P "$jobs" -I{} "$NARGO" --program-dir "$workspace" export --silence-warnings --package {}

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
ls "$artifacts_path" | sed 's/\.json$//' |
    xargs -P "$jobs" -I{} sh -c "$BACKEND gates -b '$artifacts_path/{}.json' > '$scratch/{}.json'"

for gates in "$scratch"/*.json; do
    name="$(basename "$gates" .json)"
    jq -c --arg name "$name" '{package_name: $name, functions: [.functions[0] | .name = "main"]}' "$gates"
done | jq -s '{programs: .}' > gates_report.json

jq -r '[.programs[] | {
    "name": "\(.package_name)/main",
    "unit": "acir_opcodes",
    "value": (.functions[0].acir_opcodes // 0)
}]' gates_report.json > benchmark-opcodes.json

jq -r '[.programs[] | {
    "name": "\(.package_name)/main",
    "unit": "circuit_size",
    "value": (.functions[0].circuit_size // 0)
}]' gates_report.json > benchmark-circuit.json
