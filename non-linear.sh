#!/usr/bin/env bash
# Alias for the nonlinear PoC launcher.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "$HERE/run-nonlinear.sh" "$@"
