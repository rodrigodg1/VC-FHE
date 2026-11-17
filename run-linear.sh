#!/usr/bin/env bash
# Linear Test PoC selector, followed by validated derivation and review gates.
# See docs/METRICS.md for --readiness, --list and --postprocess-only.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for arg in "$@"; do
  case "$arg" in
    --half|--half=*) echo "run-linear.sh fixes --half=linear; invoke run-poc.sh to select another scope." >&2; exit 2 ;;
  esac
done
exec "$HERE/run-poc.sh" --half linear "$@"
