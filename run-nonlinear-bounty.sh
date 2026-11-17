#!/usr/bin/env bash
# Real-data, real-FHE, Besu and threshold-KMS entry point for bounty-v2.
set -Eeuo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${VCFHE_LEGACY_EVALUATION:-0}" == 1 ]]; then
  echo "bounty-v2 cannot run through the historical pipeline" >&2; exit 2
fi
mode=full
forward=()
for arg in "$@"; do
  case "$arg" in
    --readiness) mode=readiness ;;
    --half|--half=*|--nonlinear-protocol|--nonlinear-protocol=*|--poc|--poc-readiness|--policy-refresh-v3|--smoke|--fhe-params|--fhe-params=*|--kms-threads|--kms-threads=*|--kms-tokio-threads|--kms-tokio-threads=*|--new-policy-lineage)
      echo "This entry point fixes the nonlinear bounty-v2 Test profile; use --readiness for the pilot." >&2; exit 2 ;;
    -h|--help)
      cat <<'HELP'
Usage: ./run-nonlinear-bounty.sh [--readiness] [--list | --preflight | --check --run-dir PATH | --run-dir PATH]
  --list       Inspect the plan without starting Docker, computation or releases.
  --preflight  Inspect prerequisites and retained policy state without starting them.
  --readiness  Largest-size admission pilot for both workloads, never evaluation evidence.
  --check      Validate a completed nonlinear run. Requires --run-dir PATH.
  no mode      Complete nonlinear grid: 180 measured pairs, 12 warm-ups, 30 full cases.
Uses the approved Test profile and real datasets/FHE/Besu/four-party KMS.
Initial setup applies only to an empty installation. Existing policy counters remain.
Console progress reports phases and x/y counts. Full runs derive preliminary results.
Analysis validates the measurement grid and diagnostic checks before rendering results.
--postprocess-only --run-dir PATH continues derivation without repeating experiments.
See REPRODUCE.md and docs/METRICS.md for current instructions.
HELP
      exit 0 ;;
    *) forward+=("$arg") ;;
  esac
done
profile=(--poc)
if [[ "$mode" == readiness ]]; then profile=(--poc-readiness --smoke); fi
exec "$HERE/non-linear.sh" --nonlinear-protocol bounty-v2 "${profile[@]}"   --fhe-params Test --allow-insecure-test --kms-threads 1 --kms-tokio-threads 1 ${forward[@]+"${forward[@]}"}
