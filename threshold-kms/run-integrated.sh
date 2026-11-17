#!/usr/bin/env bash
# Explicit threshold-output profile; never replaces the sealed legacy costs.
set -euo pipefail
module_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$module_dir/scripts/run-native-pilot.py" --scenario integrated "$@"
