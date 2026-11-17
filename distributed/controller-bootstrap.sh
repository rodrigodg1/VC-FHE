#!/usr/bin/env bash
# Cloud controller prerequisites only. Safe to source to retain PATH additions.
# --check is read-only. No evaluator, Docker daemon or cloud actor is started.
set -Eeuo pipefail
CONTROLLER_BOOTSTRAP_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER_BOOTSTRAP_ROOT="$(cd "$CONTROLLER_BOOTSTRAP_HERE/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
controller_apt_updated=0

controller_retry() {
  local attempt status
  for attempt in 1 2 3; do
    if "$@"; then return 0; else status=$?; fi
    # Missing administrator authorization is not a transient download failure.
    if [ "$status" = 77 ]; then return 77; fi
    if [ "$attempt" -lt 3 ]; then sleep "$((attempt * 2))"; fi
  done
  return 1
}

controller_as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"
  elif command -v sudo >/dev/null && sudo -n true 2>/dev/null; then sudo -n "$@"
  else
    echo 'Controller dependency installation requires administrator authorization. Install the listed prerequisite with your administrator, then retry. No cloud evaluation was started.' >&2
    return 77
  fi
}

controller_expose_paths() {
  if command -v brew >/dev/null; then
    local prefix
    if prefix="$(brew --prefix node@22 2>/dev/null)" && [ -d "$prefix/bin" ]; then
      export PATH="$prefix/bin:$PATH"
    fi
  fi
}

controller_install() {
  local name="$1"
  case "$(uname -s)" in
    Darwin)
      if ! command -v brew >/dev/null; then
        echo "Missing controller prerequisite $name. Homebrew is required to install it on macOS. Install Homebrew from https://brew.sh and retry. No cloud evaluation was started." >&2
        return 1
      fi
      case "$name" in
        python3|python3-venv) controller_retry brew install python ;;
        ssh|scp) controller_retry brew install openssh ;;
        node22) controller_retry brew install node@22 ;;
        *) controller_retry brew install "$name" ;;
      esac
      controller_expose_paths
      ;;
    Linux)
      if ! command -v apt-get >/dev/null; then
        echo "Missing controller prerequisite $name. Automatic installation supports Debian/Ubuntu or macOS with Homebrew. No cloud evaluation was started." >&2
        return 1
      fi
      if [ "$controller_apt_updated" = 0 ]; then
        controller_retry controller_as_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 update
        controller_apt_updated=1
      fi
      local packages=()
      case "$name" in
        python3) packages=(python3 python3-venv python3-pip) ;;
        python3-venv) packages=(python3-venv python3-pip) ;;
        ssh|scp) packages=(openssh-client) ;;
        node22)
          controller_retry controller_as_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 install -y ca-certificates curl gnupg
          local setup
          setup="$(mktemp "${TMPDIR:-/tmp}/vcfhe-node22.XXXXXX")"
          controller_retry curl --fail --silent --show-error --location https://deb.nodesource.com/setup_22.x --output "$setup"
          controller_as_root bash "$setup"
          rm -f -- "$setup"
          packages=(nodejs)
          ;;
        *) packages=("$name") ;;
      esac
      controller_retry controller_as_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 -o Acquire::Retries=3 install -y "${packages[@]}"
      if [ "$name" = node22 ] && [ -x /usr/bin/node ]; then
        # A user's version manager may still precede the installed NodeSource binary.
        export PATH="/usr/bin:$PATH"
      fi
      ;;
    *)
      echo 'Cloud controller setup requires macOS or Debian/Ubuntu/WSL2. No cloud evaluation was started.' >&2
      return 1
      ;;
  esac
}

controller_python_ready() {
  command -v python3 >/dev/null && python3 -c 'import sys; sys.exit(sys.version_info < (3,10))' >/dev/null 2>&1
}

controller_expose_installed_python() {
  local prefix directory
  if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null; then
    prefix="$(brew --prefix python)"
    for directory in "$prefix/libexec/bin" "$prefix/bin"; do
      if [ -x "$directory/python3" ] && "$directory/python3" -c 'import sys;sys.exit(sys.version_info<(3,10))'; then
        export PATH="$directory:$PATH";return 0
      fi
    done
  elif [ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'import sys;sys.exit(sys.version_info<(3,10))'; then
    export PATH="/usr/bin:$PATH"
  fi
}

controller_node_ready() {
  command -v node >/dev/null && command -v npm >/dev/null &&
    node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a===22&&b>=10?0:1)' >/dev/null 2>&1 &&
    npm --version >/dev/null 2>&1
}

controller_tool_ready() {
  command -v "$1" >/dev/null || return 1
  case "$1" in
    git|tar) "$1" --version >/dev/null 2>&1 ;;
    ssh) ssh -V >/dev/null 2>&1 ;;
    openssl) openssl version >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

controller_js_ready() {
  local directory="$1"
  node -e 'const fs=require("node:fs"),{createRequire}=require("node:module"),d=process.argv[1];const r=createRequire(d+"/package.json"),lock=JSON.parse(fs.readFileSync(d+"/package-lock.json"));for(const name of ["ethers","solc"]){const installed=JSON.parse(fs.readFileSync(d+"/node_modules/"+name+"/package.json"));if(installed.version!==lock.packages["node_modules/"+name].version)process.exit(1);r(name)}' "$directory" >/dev/null 2>&1
}

controller_plotting_check() {
  local post="$CONTROLLER_BOOTSTRAP_ROOT/threshold-kms/postprocess"
  local python="$CONTROLLER_BOOTSTRAP_ROOT/threshold-kms/.cache/postprocess-python/bin/python"
  [ -x "$python" ] || return 1
  python3 - "$post/requirements.txt" "$python" <<'PYTHON'
import hashlib
from pathlib import Path
import subprocess,sys
requirements,python=Path(sys.argv[1]),Path(sys.argv[2])
marker=python.parent.parent/'requirements.sha256'
if not marker.is_file() or marker.read_text().strip()!=hashlib.sha256(requirements.read_bytes()).hexdigest():
    raise SystemExit(1)
raise SystemExit(subprocess.run([str(python),'-c','import matplotlib,numpy'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode)
PYTHON
}

controller_plotting_install() {
  local post="$CONTROLLER_BOOTSTRAP_ROOT/threshold-kms/postprocess"
  # Reuse the existing isolated pinned environment. This imports no evaluator.
  python3 - "$post" <<'PYTHON'
import subprocess,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from refresh import plotting_python
for attempt in range(3):
    try:
        python=Path(plotting_python())
        break
    except (OSError,subprocess.CalledProcessError):
        if attempt==2:raise
        time.sleep(2*(attempt+1))
check=subprocess.run([str(python),'-c','import matplotlib,numpy'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if check.returncode:
    # A stale success marker is not evidence that installed imports still work.
    subprocess.run([str(python),'-m','ensurepip','--upgrade'],check=True)
    subprocess.run([str(python),'-m','pip','install','--disable-pip-version-check','--retries','3',
                    '--force-reinstall','-r',str(Path(sys.argv[1])/'requirements.txt')],check=True)
subprocess.run([str(python),'-c','import matplotlib,numpy'],check=True)
PYTHON
}

controller_prerequisites() {
  local mode=install option
  for option in "$@"; do
  case "$option" in
    --check) mode=check ;;
    --install) ;;
    --help|-h) echo 'Prepare cloud controller dependencies without starting Docker or an evaluation. --check never installs software.'; return 0 ;;
    *) echo 'Usage: controller-bootstrap.sh [--check|--install]' >&2; return 2 ;;
  esac
  done
  controller_expose_paths
  local missing=0 tool directory
  if ! controller_python_ready; then
    if [ "$mode" = check ]; then echo 'Missing Python >=3.10.' >&2; missing=1
    else
      controller_install python3
      controller_expose_installed_python
      controller_python_ready || { echo 'Python >=3.10 remains unavailable. No cloud evaluation was started.' >&2; return 1; }
    fi
  fi
  for tool in git ssh scp tar openssl; do
    if ! controller_tool_ready "$tool"; then
      if [ "$mode" = check ]; then echo "Missing controller tool: $tool" >&2; missing=1
      else controller_install "$tool"; controller_tool_ready "$tool" || { echo "Controller tool $tool remains unavailable." >&2; return 1; }; fi
    fi
  done
  if ! controller_node_ready; then
    if [ "$mode" = check ]; then echo 'Missing Node.js >=22.10 <23 and npm.' >&2; missing=1
    else controller_install node22; controller_node_ready || { echo 'Node.js >=22.10 <23 with npm remains unavailable.' >&2; return 1; }; fi
  fi
  if controller_python_ready; then
    if ! python3 -c 'import venv,ensurepip' >/dev/null 2>&1; then
      if [ "$mode" = check ]; then echo 'Missing Python venv/ensurepip.' >&2; missing=1
      else
        controller_install python3-venv
        python3 -c 'import venv,ensurepip' >/dev/null 2>&1 || { echo 'Python venv/ensurepip remain unavailable.' >&2; return 1; }
      fi
    fi
    if [ "$mode" = check ]; then
      if ! controller_plotting_check; then echo 'Missing or broken isolated plotting dependencies.' >&2; missing=1; fi
    else controller_plotting_install; fi
  fi
  if controller_node_ready; then
    for directory in "$CONTROLLER_BOOTSTRAP_ROOT/fhe-pod" "$CONTROLLER_BOOTSTRAP_ROOT/BN254-Signatures"; do
      if ! controller_js_ready "$directory"; then
        if [ "$mode" = check ]; then echo "Missing controller JavaScript dependencies: ${directory##*/}" >&2; missing=1
        else
          # Locked installation only. Do not rewrite package manifests or locks.
          local lock_before lock_after
          lock_before="$(python3 -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$directory/package-lock.json")"
          controller_retry npm --prefix "$directory" ci --ignore-scripts --no-audit --no-fund
          lock_after="$(python3 -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$directory/package-lock.json")"
          [ "$lock_before" = "$lock_after" ] || { echo "Dependency lock changed during controller installation: ${directory##*/}" >&2; return 1; }
          controller_js_ready "$directory" || { echo "JavaScript imports remain unavailable: ${directory##*/}" >&2; return 1; }
        fi
      fi
    done
  fi
  if [ "$missing" != 0 ]; then echo 'Controller checks failed. No packages were installed and no cloud evaluation was started.' >&2; return 1; fi
  echo 'Cloud controller dependencies ready. No Docker daemon, cloud resource or evaluation was started.'
}

controller_prerequisites "$@"
