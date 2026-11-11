#!/usr/bin/env bash
# Run the TXE tests of the use-case packages of the Aztec workspace.
#
# Usage: aztec/use-cases/scripts/test-use-cases.sh [--jobs N] [--test-threads N] [--unconstrained-contracts] [selector...]
#
# Selectors (default `all`):
#   cores                trust, the six cores (unit tests) and testing/{core_tests,family_oidc_tests} (TXE)
#   adapters             the adapter crates' unit tests and the test adapter
#   <use case>           every instance of a use case, e.g. login-link
#   <use case>/<scheme>  one instance, e.g. account-authorisation/google
#   all                  everything above
#
# By default only the small keyless shell contract `uc_terms_shell` (testing/terms_shell) is compiled and deployed; no
# example contract is. `aztec-nargo check --workspace` type-checks the instance contracts, and every TXE test runs its
# instance's core in a private context at a deployed shell. This script compiles the shell and processes it with
# `bb aztec_process` once (not again while its artifact in aztec/target is newer than its sources), when a selected
# package needs it. Then `nargo test` of each selected package, up to --jobs packages at once, each on one of up to
# 12 TXE servers (ports TXE_PORT, TXE_PORT+1, ...; scripts/txe-server.mjs, the Aztec CLI's TXE with a long keep-alive
# timeout).
#
# Options: --jobs N (default $JOBS, else cores / 4), --test-threads N (nargo's test threads per package; default
# $TEST_THREADS, else 16; CI passes 4). The defaults are below the number of cores because memory grows with both:
# a package's nargo process can need several GB (up to about 7 GB measured). --unconstrained-contracts: when
# account-authorisation/ethereum_secret_key is selected, also compile that account and testing/dispatch_target as
# Brillig (`aztec-nargo compile --force-brillig`), process them with `bb aztec_process`, and run the deploy tests of
# testing/dispatch_target, which deploy the account and send a call through its entrypoint. These artifacts are for
# tests only: never deploy them, and their addresses differ from those of constrained builds.
# Environment: TXE_PORT (default 8081), NARGO (default aztec-nargo, the Aztec 6.0.0 nargo 1.0.0-rc.3), BB (default
# aztec-bb). Logs go to aztec/target/use-cases-logs/. No proof is made and nothing is deployed to a network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
workspace="$(cd "$here/../.." && pwd)"
cd "$workspace"

NARGO="${NARGO:-aztec-nargo}"
BB="${BB:-aztec-bb}"
PORT="${TXE_PORT:-8081}"
THREADS="${TEST_THREADS:-16}"
JOBS="${JOBS:-$(($(nproc) / 4))}"
unconstrained_contracts=0
selectors=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs) JOBS="$2"; shift ;;
        --jobs=*) JOBS="${1#--jobs=}" ;;
        --test-threads) THREADS="$2"; shift ;;
        --test-threads=*) THREADS="${1#--test-threads=}" ;;
        --unconstrained-contracts) unconstrained_contracts=1 ;;
        -h | --help) sed -n '2,/^set -euo/p' "$here/${0##*/}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; exit 2 ;;
        *) selectors+=("$1") ;;
    esac
    shift
done
[[ ${#selectors[@]} -gt 0 ]] || selectors=(all)
((JOBS >= 1)) || JOBS=1
logs=target/use-cases-logs
mkdir -p "$logs"
: >"$logs/failed.list"

# role, directory, package, use case (tab-separated), from use-cases.json.
listing="$(python3 use-cases/scripts/generate.py --list)"
selected="$(
    for selector in "${selectors[@]}"; do
        case "$selector" in
            all) awk -F'\t' '$1 != "template"' <<<"$listing" ;;
            cores) awk -F'\t' '$1 == "base" || $2 == "testing/core_tests" || $2 == "testing/family_oidc_tests"' <<<"$listing" ;;
            adapters) awk -F'\t' '$1 == "adapter" || $1 == "test_adapter"' <<<"$listing" ;;
            */*) awk -F'\t' -v d="$selector" '$1 == "instance" && $2 == d' <<<"$listing" ;;
            *) awk -F'\t' -v u="$selector" '$1 == "instance" && $4 == u' <<<"$listing" ;;
        esac | grep . || { echo "No package matches '$selector'" >&2; exit 2; }
    done | awk '!seen[$0]++'
)"

tests=()
needs_shell=0
deploy_tests=0
while IFS=$'\t' read -r role directory package _; do
    case "$role" in
        instance)
            tests+=("$package")
            needs_shell=1
            [[ $unconstrained_contracts == 0 || $directory != account-authorisation/ethereum_secret_key ]] || deploy_tests=1
            ;;
        # terms_shell has no tests; dispatch_target's run with --unconstrained-contracts.
        testing)
            case "$directory" in
                testing/terms_shell | testing/dispatch_target) ;;
                *) tests+=("$package"); needs_shell=1 ;;
            esac
            ;;
        *) tests+=("$package") ;;
    esac
done <<<"$selected"

failed=()

# Whether target/uc_terms_shell-*.json exists, has been processed by bb and is newer than every source of the
# package and of its path dependencies.
shell_fresh() {
    python3 - <<'EOF'
import json, sys, tomllib
from pathlib import Path
artifacts = sorted(Path("target").glob("uc_terms_shell-*.json"))
if not artifacts or not all(json.loads(a.read_text()).get("transpiled") for a in artifacts):
    sys.exit(1)
oldest = min(a.stat().st_mtime for a in artifacts)
seen, stack = set(), [Path("use-cases/testing/terms_shell")]
while stack:
    folder = stack.pop().resolve()
    if folder in seen:
        continue
    seen.add(folder)
    for source in [folder / "Nargo.toml", *folder.rglob("*.nr")]:
        if source.stat().st_mtime > oldest:
            sys.exit(1)
    for dependency in tomllib.loads((folder / "Nargo.toml").read_text()).get("dependencies", {}).values():
        if isinstance(dependency, dict) and "path" in dependency:
            stack.append(folder / dependency["path"])
EOF
}

if [[ $needs_shell == 1 ]]; then
    if shell_fresh; then
        printf -- '-- uc_terms_shell artifact up to date, not compiled again\n'
    else
        start=$SECONDS status=0
        {
            "$NARGO" compile --package uc_terms_shell --silence-warnings --inliner-aggressiveness 0 &&
                args=() && for artifact in target/uc_terms_shell-*.json; do args+=(-i "$artifact"); done &&
                "$BB" aztec_process "${args[@]}"
        } >"$logs/compile-uc_terms_shell.log" 2>&1 || status=$?
        printf -- '-- compile testing/terms_shell: %ss, exit %s\n' $((SECONDS - start)) "$status"
        if [[ $status != 0 ]]; then
            tail -n 30 "$logs/compile-uc_terms_shell.log"
            echo "Failed: uc_terms_shell" >&2
            exit 1
        fi
    fi
fi

if [[ $deploy_tests == 1 ]]; then
    start=$SECONDS status=0
    for package in ethereum_secret_key_auth_account uc_dispatch_target; do
        {
            "$NARGO" compile --package "$package" --silence-warnings --force-brillig --inliner-aggressiveness 0 &&
                "$BB" aztec_process -i "target/$package-"*.json
        } >"$logs/compile-$package.log" 2>&1 &
    done
    for job in $(jobs -p); do wait "$job" || status=1; done
    printf -- '-- compile account-authorisation/ethereum_secret_key and testing/dispatch_target unconstrained: %ss, exit %s\n' \
        $((SECONDS - start)) "$status"
    if [[ $status != 0 ]]; then
        tail -n 30 "$logs"/compile-{ethereum_secret_key_auth_account,uc_dispatch_target}.log
        echo "Failed: unconstrained contracts" >&2
        exit 1
    fi
    tests+=(uc_dispatch_target)
fi

# Jobs record their failures in failed.list: `wait -n` in throttle may already have reaped them.
job_pids=()
running() { local n=0 pid; for pid in ${job_pids[@]+"${job_pids[@]}"}; do ! kill -0 "$pid" 2>/dev/null || n=$((n + 1)); done; echo "$n"; }
throttle() { while (($(running) >= JOBS)); do wait -n || true; done; }
collect() { local pid; for pid in ${job_pids[@]+"${job_pids[@]}"}; do wait "$pid" 2>/dev/null || true; done; job_pids=(); mapfile -t -O "${#failed[@]}" failed <"$logs/failed.list"; : >"$logs/failed.list"; }

run_tests() { # package port
    local package="$1" port="$2" start=$SECONDS status=0
    "$NARGO" test --package "$package" --silence-warnings --oracle-resolver "http://127.0.0.1:$port" \
        --test-threads "$THREADS" --inliner-aggressiveness 0 >"$logs/test-$package.log" 2>&1 || status=$?
    printf -- '-- test %s: %ss, exit %s, %s\n' "$package" $((SECONDS - start)) "$status" \
        "$(sed 's/\x1b\[[0-9;]*m//g' "$logs/test-$package.log" | grep -E '^\[[a-z0-9_]+\] [0-9]+ tests? (passed|failed)' |
            sed 's/^\[[^]]*\] //' | tr '\n' ' ')"
    [[ $status == 0 ]] || { grep -v '^\s*$' "$logs/test-$package.log" | tail -n 40; echo "$package" >>"$logs/failed.list"; }
}

servers=$((JOBS < ${#tests[@]} ? JOBS : ${#tests[@]}))
((servers <= 12)) || servers=12
txe_pids=()
trap 'kill ${txe_pids[@]+"${txe_pids[@]}"} 2>/dev/null || true' EXIT
for ((i = 0; i < servers; i++)); do
    # `aztec start --txe` with a long HTTP keep-alive timeout (see txe-server.mjs).
    LOG_LEVEL="${LOG_LEVEL:-error}" node ../scripts/txe-server.mjs $((PORT + i)) \
        >"$logs/txe-$((PORT + i)).log" 2>&1 &
    txe_pids+=($!)
done
for ((i = 0; i < servers; i++)); do
    until nc -z 127.0.0.1 $((PORT + i)) 2>/dev/null; do
        kill -0 "${txe_pids[$i]}" 2>/dev/null ||
            { echo "TXE failed to start; see aztec/$logs/txe-$((PORT + i)).log" >&2; exit 1; }
        sleep 0.5
    done
done
export NARGO_FOREIGN_CALL_TIMEOUT="${NARGO_FOREIGN_CALL_TIMEOUT:-300000}"
printf '\n== test phase (%s packages, %s at once, %s TXE servers, %s test threads each)\n' \
    "${#tests[@]}" "$JOBS" "$servers" "$THREADS"
i=0
for package in "${tests[@]}"; do
    throttle
    run_tests "$package" $((PORT + i % servers)) &
    job_pids+=($!)
    i=$((i + 1))
done
collect
if [[ ${#failed[@]} -gt 0 ]]; then
    printf '\nFailed: %s\n' "${failed[*]}" >&2
    exit 1
fi
