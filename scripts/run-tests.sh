#!/usr/bin/env bash
# Run the tests of noir/ packages. Per pull request every test runs as unconstrained Brillig
# (`--force-brillig --inliner-aggressiveness 0`: seconds where constrained execution takes minutes); with
# --nightly it runs as written, so constrained code executes as ACIR, with the thread count
# scripts/nightly-threads.txt gives the package (default 4) so that it fits a 16 GB runner.
#
#   ./scripts/run-tests.sh [--package P]... [--workspace] [--nightly] [--test-threads N] [--jobs N] [nargo args]
#
#   --package P        a noir/ workspace member (repeatable); without it, or with --workspace, every member
#   --nightly          constrained mode
#   --test-threads N   nargo's test threads per package (default: the number of cores, or the nightly count
#                      from scripts/nightly-threads.txt; CI passes 4 per pull request)
#   --jobs N           packages tested at once (default 1: each package already uses every core, and memory
#                      grows with both counts)
#
# Other arguments go to nargo ($NARGO, else nargo on PATH).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
NARGO="${NARGO:-nargo}"

packages=()
nightly=false
threads=""
max_jobs=1
args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --package) packages+=("$2"); shift 2 ;;
        --package=*) packages+=("${1#--package=}"); shift ;;
        --workspace) packages=(); shift ;;
        --nightly) nightly=true; shift ;;
        --test-threads) threads="$2"; shift 2 ;;
        --test-threads=*) threads="${1#--test-threads=}"; shift ;;
        --jobs) max_jobs="$2"; shift 2 ;;
        --jobs=*) max_jobs="${1#--jobs=}"; shift ;;
        -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) args+=("$1"); shift ;;
    esac
done
if [[ ${#packages[@]} -eq 0 ]]; then
    mapfile -t packages < <(sed -n 's/^ *"\(.*\)",$/\1/p' "$root/noir/Nargo.toml")
fi

failed=()
pids=()
names=()
for package in "${packages[@]}"; do
    if [[ $nightly == true ]]; then
        count="${threads:-$(awk -v p="$package" '!/^#/ && $1 == p { print $2 }' "$root/scripts/nightly-threads.txt")}"
        flags=(--test-threads "${count:-4}")
    else
        flags=(--test-threads "${threads:-$(nproc)}" --force-brillig --inliner-aggressiveness 0)
    fi
    while (($(jobs -rp | wc -l) >= max_jobs)); do wait -n || true; done
    "$NARGO" --program-dir "$root/noir" test --package "$package" "${flags[@]}" ${args[@]+"${args[@]}"} &
    pids+=($!)
    names+=("$package")
done
for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || failed+=("${names[$i]}")
done
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "Failed: ${failed[*]}" >&2
    exit 1
fi
