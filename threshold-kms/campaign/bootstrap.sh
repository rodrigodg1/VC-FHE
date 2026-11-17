#!/usr/bin/env bash
# Install host prerequisites for the isolated execution and analysis services.
# Rust/Node/build tools live in images. Inspection and derivation skip this setup.
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
install_missing() {
  case "$(uname -s)" in
    Darwin)
      if ! command -v brew >/dev/null; then
        echo "Homebrew is required to install missing prerequisites. Install it from https://brew.sh and retry." >&2
        exit 1
      fi
      case "$1" in
        docker) brew install --cask docker ;;
        docker-compose-v2)
          brew install docker-compose
          local plugin_dir="${DOCKER_CONFIG:-${HOME}/.docker}/cli-plugins"
          local compose_bin="$(brew --prefix docker-compose)/bin/docker-compose"
          mkdir -p "$plugin_dir"
          if [ ! -e "$plugin_dir/docker-compose" ] && [ ! -L "$plugin_dir/docker-compose" ]; then
            ln -s "$compose_bin" "$plugin_dir/docker-compose"
          fi ;;
        python3|python3-venv) brew install python ;;
        *) brew install "$1" ;;
      esac ;;
    Linux)
      local elevate=()
      if [ "$(id -u)" != 0 ]; then
        if ! sudo -n true 2>/dev/null; then
          echo "Missing $1. Administrator authorization is needed to install it; run the prerequisite installation with sudo and retry." >&2; exit 1
        fi
        elevate=(sudo -n)
      fi
      # Preserve empty-array expansion under Bash 3 with nounset enabled.
      if command -v apt-get >/dev/null; then
        ${elevate[@]+"${elevate[@]}"} apt-get update
        case "$1" in
          docker) ${elevate[@]+"${elevate[@]}"} apt-get install -y docker.io docker-compose-v2 ;;
          *) ${elevate[@]+"${elevate[@]}"} apt-get install -y "$1" ;;
        esac
      else echo "Unsupported package manager: install Python 3 with venv/pip, Git and Docker with Compose v2, then retry." >&2; exit 1; fi ;;
    *) echo "Use Linux/WSL2 or macOS for this campaign." >&2; exit 1 ;;
  esac
}
# Help/plan never installs software or starts infrastructure.
readonly_only=0
for arg in "$@"; do case "$arg" in --help|-h|--list|--check|--preflight|--postprocess-only|--explain-threshold-scaling) readonly_only=1 ;; esac; done
if [ "$readonly_only" = 1 ]; then
  command -v python3 >/dev/null || { echo 'Python 3 is required to inspect the campaign.' >&2; exit 1; }
  exec python3 "$HERE/run.py" "$@"
fi
if [ -f /.dockerenv ]; then
  echo 'Launch run-linear.sh, non-linear.sh or run-poc.sh on the host (or WSL2 with Docker integration). The campaign provisions isolated containers; it must not run inside the legacy evaluator or acquire its Docker socket.' >&2
  exit 1
fi
for tool in python3 git docker; do
  if ! command -v "$tool" >/dev/null; then
    [ "$readonly_only" = 0 ] || { echo "Missing prerequisite: $tool" >&2; exit 1; }
    install_missing "$tool"
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  [ "$readonly_only" = 0 ] || { echo "Docker Compose v2 is missing" >&2; exit 1; }
  install_missing docker-compose-v2
  docker compose version >/dev/null
fi
# Prepare the same isolated, pinned plotting environment used after sealing.
# Fail here, rather than after hours of experiments, if venv/pip/downloads fail.
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
  install_missing python3
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
  echo 'Matplotlib requires Python 3.10 or later. Make that python3 available in PATH and retry. No campaign was started.' >&2
  exit 1
}
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
  install_missing python3-venv
fi
python3 - "$HERE/../postprocess" <<'PYTHON'
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
from refresh import plotting_python
import subprocess
subprocess.run([str(plotting_python()), '-c', 'import matplotlib'], check=True)
PYTHON
exec python3 "$HERE/run.py" "$@"
