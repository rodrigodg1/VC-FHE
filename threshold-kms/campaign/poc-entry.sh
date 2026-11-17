#!/usr/bin/env bash
# Current evaluation defaults. The low-level runner retains explicit historical profiles.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
half=both
profile=(--poc)
protocol=(--nonlinear-protocol bounty-v2)
forward=()
previous=''
for arg in "$@"; do
  if [[ "$previous" == --half ]]; then half="$arg"; fi
  case "$arg" in
    --half=*) half="${arg#*=}" ;;
    --poc|--poc-readiness) profile=() ;;
    --smoke) profile=(--poc-readiness) ;;
    --policy-refresh-v3) profile=(); protocol=() ;;
    --readiness) profile=(--poc-readiness --smoke); previous="$arg"; continue ;;
    --new-policy-lineage) echo 'Current evaluation runs preserve the existing release-policy lineage.' >&2; exit 2 ;;
  esac
  forward+=("$arg")
  previous="$arg"
done
if [[ "$half" == linear ]]; then protocol=(); fi
exec bash "$HERE/bootstrap.sh" --fhe-params Test --allow-insecure-test \
  --kms-threads 1 --kms-tokio-threads 1 --auto-policy-setup ${profile[@]+"${profile[@]}"} ${protocol[@]+"${protocol[@]}"} ${forward[@]+"${forward[@]}"}
