#!/usr/bin/env bash
# Combined proof-of-concept launcher. Use --list or --preflight before execution.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$(uname -s)" = Darwin ] && command -v caffeinate >/dev/null && [ "${VCFHE_CAFFEINATED:-0}" != 1 ]; then
  export VCFHE_CAFFEINATED=1
  exec caffeinate -i bash "$0" "$@"
fi
exec bash "$HERE/threshold-kms/campaign/poc-entry.sh" "$@"
