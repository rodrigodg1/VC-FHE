#!/usr/bin/env bash
# Offline by default. setup/cloud-build/cloud-run explicitly contact GCP.
# ./run-distributed.sh plan
# ./run-distributed.sh prepare --output /absolute/new/directory
# ./run-distributed.sh test
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" = test ]; then
  shift
  exec "$HERE/distributed/cloud_results/run.sh" test "$@"
fi
if [ "${1:-}" = cloud-results ]; then
  shift
  exec "$HERE/distributed/cloud_results/run.sh" "$@"
fi
if [ "${1:-}" = dependencies ]; then
  shift
  # No args is read-only. Explicit --install resolves controller tools only.
  if [ "$#" = 0 ]; then set -- --check; fi
  source "$HERE/distributed/controller-bootstrap.sh" "$@"
  exit $?
fi
needs_setup=0
case "${1:-}" in cloud-build|cloud-run|launch) needs_setup=1 ;; esac
for option in "$@"; do case "$option" in --help|-h) needs_setup=0 ;; esac; done
if [ "$needs_setup" = 1 ]; then
  # Keep exported tool paths in this process. This never dispatches an experiment.
  source "$HERE/distributed/controller-bootstrap.sh" --install
fi
exec python3 "$HERE/distributed/cli.py" "$@"
