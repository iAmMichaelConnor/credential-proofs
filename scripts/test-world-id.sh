#!/usr/bin/env bash
# Run the World ID gate tests (aztec/world-id-v3, aztec/world-id-v4) concurrently against
# one TXE. By default no contract is compiled: the tests run the gates' logic in TXE test contexts.
# Usage: TXE_PORT=8081 ./scripts/test-world-id.sh [--test-threads N] [--unconstrained-contracts]
#   --test-threads N   test threads per package (default: number of cores; CI passes 4)
#   --unconstrained-contracts
#                      also compile both gates as Brillig (`aztec-nargo compile --force-brillig`), process them
#                      with `aztec-bb aztec_process`, and run the deploy tests (aztec/world-id-deploy-tests),
#                      which deploy those artifacts and call them. These artifacts are for tests only: never
#                      deploy them, and their addresses differ from those of constrained builds.
# Needs the Aztec 6.0.0 toolchain (aztec, aztec-nargo, aztec-bb) and Node on PATH.
set -euo pipefail
cd "$(dirname "$0")/../aztec"
port="${TXE_PORT:-8081}"
threads="$(nproc)"
packages=(world_id3_gate_tests world_id4_gate world_id4_gate_tests)
unconstrained_contracts=false
while [ $# -gt 0 ]; do
  case "$1" in
    --test-threads) threads="$2"; shift 2 ;;
    --unconstrained-contracts) unconstrained_contracts=true; shift ;;
    *) echo "Usage: TXE_PORT=8081 $0 [--test-threads N] [--unconstrained-contracts]" >&2; exit 2 ;;
  esac
done

mkdir -p target
if $unconstrained_contracts; then
  for gate in world_id3_gate world_id4_gate; do
    {
      aztec-nargo compile --package "$gate" --silence-warnings --force-brillig --inliner-aggressiveness 0 &&
        aztec-bb aztec_process -i "target/$gate-"*.json
    } > "target/compile-$gate.log" 2>&1 &
  done
  for job in $(jobs -p); do
    wait "$job" || { tail -n 30 target/compile-world_id*_gate.log; echo "Compiling the gates failed" >&2; exit 1; }
  done
  packages+=(world_id_deploy_tests)
fi

node ../scripts/txe-server.mjs "$port" > "target/txe-$port.log" 2>&1 &
txe=$!
pids=()
trap 'kill "$txe" "${pids[@]}" 2>/dev/null || true' EXIT
until nc -z 127.0.0.1 "$port" 2>/dev/null; do
  kill -0 "$txe" 2>/dev/null || { echo "TXE failed to start; see aztec/target/txe-$port.log" >&2; exit 1; }
  sleep 0.5
done

# A claim runs the whole Groth16 verifier between two oracle calls.
export NARGO_FOREIGN_CALL_TIMEOUT="${NARGO_FOREIGN_CALL_TIMEOUT:-1800000}"
for package in "${packages[@]}"; do
  aztec-nargo test --package "$package" --silence-warnings \
    --oracle-resolver "http://127.0.0.1:$port" --test-threads "$threads" &
  pids+=($!)
done
status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done
exit $status
