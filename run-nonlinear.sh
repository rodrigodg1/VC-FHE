#!/usr/bin/env bash
# Nonlinear Test PoC selector, bounty V2 by default.
# See docs/METRICS.md for --readiness, --list and --postprocess-only.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for arg in "$@"; do
  case "$arg" in
    --half|--half=*) echo "run-nonlinear.sh fixes --half=nonlinear; invoke run-poc.sh to select another scope." >&2; exit 2 ;;
  esac
done
exec "$HERE/run-poc.sh" --half nonlinear "$@"
