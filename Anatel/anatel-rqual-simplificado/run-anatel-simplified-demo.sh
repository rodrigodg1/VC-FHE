#!/usr/bin/env bash
# ============================================================================
#  VC-FHE  —  ANATEL RQUAL quality seal  (SIMPLIFIED TEACHING DEMONSTRATION)
# ============================================================================
#  One command. Same expression, same pipeline and same contracts as
#  Anatel/anatel-rqual/, on the SMALLEST trace that still carries the whole structure:
#  28 useful leaves padded to 32, against 89 padded to 128. Built for explaining
#  how a formula becomes opcodes, not for evidence about scale.
#
#     technical measurements  -> IQS
#     user survey responses   -> IQP = ISG
#     user complaints         -> IR = 1000 * A_P / B_P
#     S = F(IQS) + F(IQP) + F(IR)   ->   regulatory quality seal
#
#  chain up (4-validator Besu QBFT) -> build the inputs from the DECLARED
#  parameters of this directory (nothing here is measured; see WHERE THE DATA
#  COMES FROM below) -> lower the expression to the 15-operation micro-ISA ->
#  commit the trace -> auditors -> a challenge -> full trace disclosure ->
#  bisection -> homomorphic leaf decision attested by t+1 signatures -> slashing.
#
#  WHAT THIS DEMONSTRATES
#  ----------------------
#  That a formula written in a government regulation can be translated into the
#  adjudicated micro-ISA trace and verified on-chain, and that the operator who
#  inflates its own seal is caught by one leaf, not by a majority vote.
#
#  WHAT IT DOES NOT DEMONSTRATE  (say this out loud in the meeting)
#  ---------------------------------------------------------------
#  It does NOT reproduce ANATEL's official numbers. Only the STRUCTURE of the
#  expression was verified against the regulation: Res. 717/2019 Art. 7 defines
#  IQS (item VI), IQP (item VII) and IR (item V), and Art. 11 assigns quality
#  seals A to E. The regulation does NOT publish the F(.) mapping or any numeric
#  band edge - those live in Anexo I / Res. Interna 444/2025, which was NOT
#  consulted. Every weight, threshold, band edge and seal cut-off used here is a
#  DECLARED DEPLOYMENT PARAMETER, listed with its own note in
#  Anatel/anatel-rqual-simplificado/anatel-rqual-simplified-params.json, chosen in the range of such
#  reference values. The seal this run releases is NOT an official RQUAL result.
#
#  WHERE THE DATA COMES FROM
#  -------------------------
#  NOWHERE. Nothing in this variant is measured. IQS and IQP are supplied as
#  pre-aggregated encrypted indicators, and A_P and B_P are illustrative period
#  constants, all four declared with an explicit _source in the parameter file.
#  The full demonstration in Anatel/anatel-rqual/ is the one that reads real panels:
#  16 drive-test milli-MOS values (5G-QoERA) and 20 ACR scores from 20 human
#  subjects (WebRTC-QoE, Zenodo 15836614, CC BY 4.0). If you want a run over
#  measured records, run that one.
#
#  TWO DELIBERATE DIFFERENCES FROM Anatel/anatel-rqual/, say both when showing both:
#    1. IQS and IQP are given, not computed from a panel: 34 accumulation leaves
#       and four MUL/DIV leaves disappear with the panels.
#    2. F(.) uses THREE band edges here and four there, which removes two more
#       leaves per indicator and makes the two runs assign different bands to
#       the same indicator. The seals therefore differ, by construction.
#
#  This demonstration is SEPARATE from the implementation's evaluation. Its workload
#  is not a member of allApplicationWorkloadSpecs(); it writes nothing into the
#  canonical artifact set; the eleven evaluated workloads are untouched.
#
#  Outputs:
#     fhe-pod/artifacts/runs/anatel-rqual-simplified-demo-<stamp>/   trace + receipts
#     fhe-pod/artifacts/evaluations/anatel-rqual-simplified-demo/    the run record
#
# ----------------------------------------------------------------------------
#  >>> KNOBS (tuned for a LIVE MEETING: short windows, fast narration) <<<
# ----------------------------------------------------------------------------
#  The four window knobs below are OVERRIDES. Unset, they are not fixed defaults:
#  they are computed further down from the block period this script MEASURES at
#  the endpoint, with floors of 45 s, 45 s, 30 s and 180 s. On the 2-second QBFT
#  network that yields 48 s, 48 s, 32 s and 180 s. Set one only to override the
#  measurement, and read the sizing rule before lowering any of them.
#  DEMO_COMMIT_WINDOW_SECONDS      auditor commit window       measured, floor  45
#  DEMO_OPEN_WINDOW_SECONDS        auditor reveal window       measured, floor  45
#  DEMO_CHALLENGE_WINDOW_SECONDS   challenge window            measured, floor  30
#  DEMO_DISCLOSURE_WINDOW_SECONDS  trace-disclosure window     measured, floor 180
#     Sizing rule for the disclosure window (do not lower it blindly): a trace
#     of N leaves published k at a time needs ceil(N/k) STRICTLY SEQUENTIAL
#     batches, so the window must exceed that many block inclusions plus a
#     finality margin. This trace is 32 leaves, a quarter of the full
#     demonstration's, so disclosure needs four sequential batches, not sixteen.
#
#  RPC_URL     JSON-RPC endpoint.  default http://127.0.0.1:8550
#              Set it to attach an already-running chain. If nothing answers
#              there and the endpoint is LOCAL, the script brings up the
#              4-validator Besu QBFT network itself rather than failing; a
#              remote endpoint that is down is still an error, because nothing
#              this script can run here would fix it.
#  ATTACH_ONLY=1
#              never start a chain. With RPC_URL set and nothing answering, the
#              script stops instead of running docker compose. Use it when the
#              endpoint belongs to someone else's run.
#  CHAIN_ID    expected chain id.  default 46853  (the 4-validator QBFT net)
#  MNEMONIC    funding mnemonic.   default: the genesis dev mnemonic
#  DRY_RUN=1   build, verify and print the trace and the reference values;
#              contact no chain, spawn nothing, write nothing.
#  NARRATE=1   stage-by-stage narration of the lowering, one act per stage of
#              the formula, following the walkthrough deck act by act. Contacts
#              no chain, spawns nothing, writes nothing. This is the mode to
#              project in a meeting: DRY_RUN prints the finished trace, NARRATE
#              shows the formula turning into it.
#              NARRATE_PAUSE=1   wait for Enter between acts
#              NARRATE_SLOW=<s>  auto-advance every <s> seconds instead
#              NARRATE_LEAVES=1  accepted and inert. The full demonstration
#                                elides its 128 leaves and needs this switch;
#                                32 leaves always print in full, so this
#                                narrator takes `--leaves` and ignores it.
#              NARRATE_ACT=<n>   print only these acts: 5, or 1-5, or 0,2,5
#                                (this narrator has nine acts, 0 to 8)
#  NARRATE_INLINE=0
#              turn OFF the narration that the FULL run prints inside phases 5,
#              6 and 7. It is on by default: phase 5 shows the uint64 registers
#              and the leaves each stage of the formula produced, phase 6 shows
#              what the encrypted execution does to them, and phase 7 shows the
#              bisection ladder the dispute is about to walk. With it off, those
#              phases print the terse two-line announcements only.
#  MANIPULATED_LEAF_INDEX=<n>      corrupt leaf n instead of the seal leaf.
#  REFRESH_FHE=1 re-run the TFHE executor even when a manifest for this exact
#              trace already exists.
#
#  ENCRYPTED EXECUTION. Every operand handle this demonstration registers on
#  chain is keccak256 of a serialized TFHE ciphertext, produced by executing
#  this trace over FheUint64 values with tfhe-rs. Both variants, honest and
#  corrupted, are executed, and every leaf is decrypted and compared against
#  the value the lowering claims. The manifest is cached under
#  fhe-pod/artifacts/fhe/anatel-simplified-demo/, so the slow step runs once. RUN IT ONCE
#  BEFORE A LIVE DEMONSTRATION: 64 leaves under encryption are a quarter of the
#  full demonstration's 256, but the first cargo build of tfhe-rs still takes
#  minutes on its own.
#
#  Examples:
#     Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh                      # start the chain, run the demo
#     DRY_RUN=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh            # rehearse with no chain at all
#     NARRATE=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh            # narrate the lowering, act by act
#     NARRATE=1 NARRATE_PAUSE=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh   # ... one act per keypress
#     RPC_URL=http://127.0.0.1:8550 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh   # attach, do not start
#     DEMO_DISCLOSURE_WINDOW_SECONDS=120 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh   # slower chain
#     REFRESH_FHE=1 Anatel/anatel-rqual-simplificado/run-anatel-simplified-demo.sh        # re-encrypt and re-execute
# ----------------------------------------------------------------------------
# Windows are sized below from the MEASURED block period once the endpoint is
# known; these are only the floors. Eight seconds looked fine on an in-process
# EVM, where a transaction mines the instant it is sent, and failed on the QBFT
# network with WrongPhase(): each auditor's submitAudit needs its own block, and
# three sequential inclusions at ~8 s each overran an 8 s commit window.
DEMO_COMMIT_WINDOW_SECONDS="${DEMO_COMMIT_WINDOW_SECONDS:-}"
DEMO_OPEN_WINDOW_SECONDS="${DEMO_OPEN_WINDOW_SECONDS:-}"
DEMO_CHALLENGE_WINDOW_SECONDS="${DEMO_CHALLENGE_WINDOW_SECONDS:-}"
DEMO_DISCLOSURE_WINDOW_SECONDS="${DEMO_DISCLOSURE_WINDOW_SECONDS:-}"
CHAIN_ID="${CHAIN_ID:-46853}"
MNEMONIC="${MNEMONIC:-test test test test test test test test test test test junk}"
DRY_RUN="${DRY_RUN:-0}"
ATTACH_ONLY="${ATTACH_ONLY:-0}"
NARRATE="${NARRATE:-0}"
NARRATE_PAUSE="${NARRATE_PAUSE:-0}"
NARRATE_SLOW="${NARRATE_SLOW:-}"
NARRATE_LEAVES="${NARRATE_LEAVES:-0}"
NARRATE_ACT="${NARRATE_ACT:-}"
REFRESH_FHE="${REFRESH_FHE:-0}"
MANIPULATED_LEAF_INDEX="${MANIPULATED_LEAF_INDEX:-}"
# ----------------------------------------------------------------------------
set -euo pipefail

# Resolve the repository root two levels above this demonstration directory.
# The pod and validator network are located relative to that root.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
BESU_COMPOSE="$REPO_ROOT/network/validators-besu/docker-compose.besu.yml"

banner() {
  echo "============================================================"
  echo " $1"
  echo "============================================================"
}

say() {
  echo
  echo "[$1] $2"
}

# ---------------------------------------------------------------------------
# Keep the machine awake. Same guard as run-nonlinear.sh: on macOS, idle sleep
# freezes Docker's VM, the validators stop producing blocks, and every in-flight
# receipt wait fails on wake with a wall-clock timeout that looks like a chain
# fault but is not one. A live demo is exactly when that must not happen.
# ---------------------------------------------------------------------------
if [ "$(uname -s)" = "Darwin" ] && [ -z "${VCFHE_CAFFEINATED:-}" ] \
   && command -v caffeinate >/dev/null 2>&1; then
  export VCFHE_CAFFEINATED=1
  exec caffeinate -ims "$0" "$@"
fi

banner "VC-FHE  |  ANATEL RQUAL quality seal  |  SIMPLIFIED teaching demonstration"
echo
echo "  Structure verified against Res. 717/2019 (Art. 7: IQS, IQP, IR; Art. 11: seals A-E)."
echo "  Every threshold, band edge and cut-off below is a DECLARED DEPLOYMENT PARAMETER,"
echo "  chosen in the range of such reference values - NOT prescribed by ANATEL."
echo "  This run does NOT reproduce ANATEL's official numbers, and NOTHING in this"
echo "  variant is measured data: it is the teaching trace, 28 leaves padded to 32."

# Expanded through the "${arr[@]+...}" form below: under `set -u`, bash 3.2 (the
# /bin/bash macOS ships) treats "${arr[@]}" on an empty array as an unbound
# variable and aborts. The form is a no-op on newer bash. HAVE_DEMO_ARGS exists
# for the same reason on the npm side: `npm run <script> --` with nothing after
# the separator is not worth relying on, so the empty case runs a plain command.
DEMO_ARGS=()
HAVE_DEMO_ARGS=0
if [ -n "$MANIPULATED_LEAF_INDEX" ]; then
  DEMO_ARGS+=(--manipulated-leaf-index "$MANIPULATED_LEAF_INDEX")
  HAVE_DEMO_ARGS=1
fi
if [ "$REFRESH_FHE" = "1" ]; then
  DEMO_ARGS+=(--refresh-fhe)
  HAVE_DEMO_ARGS=1
fi

# -------------------------------------------------------------- 0. narrate --
# Stage-by-stage narration of the lowering. Same trace, same lowering function,
# same micro-ISA re-check as every other mode; the difference is that it is
# printed one stage of the formula at a time instead of as an aggregate. It
# needs no chain, no Docker and no installed dependency tree, so it is the mode
# to fall back on if anything else fails during a live meeting.
if [ "$NARRATE" = "1" ]; then
  NARRATE_ARGS=()
  [ "$NARRATE_PAUSE" = "1" ] && NARRATE_ARGS+=(--pause)
  [ -n "$NARRATE_SLOW" ] && NARRATE_ARGS+=(--slow "$NARRATE_SLOW")
  [ "$NARRATE_LEAVES" = "1" ] && NARRATE_ARGS+=(--leaves)
  [ -n "$NARRATE_ACT" ] && NARRATE_ARGS+=(--act "$NARRATE_ACT")
  say "0/8" "NARRATION — walking the formula into the trace, one stage at a time."
  node "$HERE/narrate-anatel-simplified.mjs" ${NARRATE_ARGS[@]+"${NARRATE_ARGS[@]}"}
  echo
  banner "Narration complete. No chain was contacted and nothing was written."
  exit 0
fi

# --------------------------------------------------------------- 0. dry run --
if [ "$DRY_RUN" = "1" ]; then
  say "0/8" "DRY RUN — building and printing the trace only. No chain is contacted."
  cd "$REPO_ROOT/fhe-pod"
  node "$HERE/run-anatel-rqual-simplified-demo.mjs" --dry-run ${DEMO_ARGS[@]+"${DEMO_ARGS[@]}"}
  echo
  banner "Dry run complete. Nothing was spawned and nothing was written."
  exit 0
fi

# ----------------------------------------------------------------- 1. chain --
# Self-starting unless RPC_URL is set. When the caller names an endpoint we
# attach to it and never touch its lifecycle.
STARTED_CHAIN=0
ATTACHED_ENDPOINT=0

rpc_call() {  # rpc_call <method> [params-json]
  curl -s -m 5 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" \
    "$RPC_URL" 2>/dev/null || true
}
rpc_result() { rpc_call "$1" "${2:-[]}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'; }

# Brings up the 4-validator Besu QBFT network and waits for it to answer.
# Factored out of the branch below because BOTH paths need it now: the default
# path, and the path where the caller named a local endpoint that is not up. It
# sets STARTED_CHAIN=1 so the teardown hint at the end is only printed when this
# script is the one that started the network.
start_besu_network() {
  if [ ! -f "$BESU_COMPOSE" ]; then
    echo "ERROR: $BESU_COMPOSE not found; cannot self-start the chain." >&2
    echo "       Start a chain yourself and re-run with RPC_URL=<endpoint>." >&2
    exit 1
  fi
  # Check the daemon before invoking compose: `docker compose up` on a host
  # without a running daemon fails with a message about the socket, which
  # reads like a bug in this script rather than a missing prerequisite.
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed, so the validator network cannot be started here." >&2
    echo "       Start a chain elsewhere and attach with RPC_URL=<endpoint>." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: the docker daemon is not responding; start Docker and try again." >&2
    echo "       Or attach an already-running chain with RPC_URL=<endpoint>." >&2
    exit 1
  fi
  docker compose -f "$BESU_COMPOSE" up -d || {
    echo "ERROR: 'docker compose up' failed for $BESU_COMPOSE." >&2
    echo "       Inspect it with: docker compose -f $BESU_COMPOSE logs --tail 50" >&2
    exit 1
  }
  STARTED_CHAIN=1
  echo "      waiting for the validators to answer (key and genesis generation on first start)"
  for _ in $(seq 1 60); do
    [ -n "$(rpc_result eth_chainId)" ] && break
    sleep 5
  done
  if [ -z "$(rpc_result eth_chainId)" ]; then
    echo "ERROR: the validators did not answer at $RPC_URL within 300 s." >&2
    echo "       Inspect them with: docker compose -f $BESU_COMPOSE logs --tail 50" >&2
    exit 1
  fi
}

# Is this endpoint on this machine? Only then may the script bring up a local
# network on the caller's behalf; a remote endpoint that is down is not
# something `docker compose up` here can fix.
is_local_endpoint() {
  case "$1" in
    *://127.0.0.1:*|*://localhost:*|*://[::1]:*|*://0.0.0.0:*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ -n "${RPC_URL:-}" ]; then
  ATTACHED_ENDPOINT=1
  say "1/8" "CHAIN — attaching to the endpoint you gave me: $RPC_URL"
  if [ -n "$(rpc_result eth_chainId)" ]; then
    echo "      it is up; this script starts and stops nothing"
  elif [ "$ATTACH_ONLY" = "1" ]; then
    echo "ERROR: nothing answered at $RPC_URL and ATTACH_ONLY=1 forbids starting a chain." >&2
    exit 1
  elif is_local_endpoint "$RPC_URL"; then
    # The rehearsal instructions tell you to pass RPC_URL on the day of the
    # meeting so the run reuses the cached ciphertext manifest. Exiting with
    # "no endpoint answered" at that moment is the worst possible behaviour,
    # so a LOCAL endpoint that is down is started here instead.
    echo "      nothing answered there yet; it is a local endpoint, so starting the"
    echo "      4-validator Hyperledger Besu QBFT network with docker compose"
    echo "      (set ATTACH_ONLY=1 if you would rather this script never started anything)"
    start_besu_network
  else
    echo "ERROR: nothing answered at $RPC_URL, and it is not a local endpoint," >&2
    echo "       so this script cannot start it. Start that chain and re-run," >&2
    echo "       or drop RPC_URL to use the local 4-validator QBFT network." >&2
    exit 1
  fi
else
  RPC_URL="http://127.0.0.1:8550"
  say "1/8" "CHAIN — 4-validator Hyperledger Besu QBFT network on $RPC_URL"
  if [ -n "$(rpc_result eth_chainId)" ]; then
    echo "      already up; reusing it"
  else
    echo "      not up yet; starting it with docker compose"
    start_besu_network
  fi
fi

# `|| true` is required, not decorative: under `set -euo pipefail` a curl that
# finds nothing listening exits 7 and would abort the script AT THIS
# ASSIGNMENT, so the diagnostic below would never print.
CHAIN_ID_HEX="$(curl -s -m 5 -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  "$RPC_URL" 2>/dev/null | sed -n 's/.*"result":"\([^"]*\)".*/\1/p' || true)"
if [ -z "$CHAIN_ID_HEX" ]; then
  echo "ERROR: no JSON-RPC endpoint answered at $RPC_URL" >&2
  echo "       Start the 4-validator QBFT network first:" >&2
  echo "         docker compose -f $BESU_COMPOSE up -d" >&2
  echo "       Or attach an endpoint of your own with RPC_URL=<endpoint>." >&2
  exit 1
fi
OBSERVED_CHAIN_ID=$((CHAIN_ID_HEX))
if [ "$OBSERVED_CHAIN_ID" != "$CHAIN_ID" ]; then
  echo "ERROR: $RPC_URL reports chain id $OBSERVED_CHAIN_ID, expected $CHAIN_ID." >&2
  echo "       Refusing to demonstrate on the wrong chain. Override with CHAIN_ID=<id>." >&2
  exit 1
fi
echo "      chain id $OBSERVED_CHAIN_ID confirmed"

# Answering eth_chainId is not the same as being able to include a transaction.
# A QBFT validator answers RPC before the round reaches quorum, and every
# transaction of this demonstration would then sit in the pool until a timeout.
# Require the head to advance before deploying anything.
say "1/8" "CHAIN — waiting for block production"
HEAD_BEFORE=$((0x0$(rpc_result eth_blockNumber | sed 's/^0x//')))
PRODUCING=0
for _ in $(seq 1 30); do
  HEAD_NOW=$((0x0$(rpc_result eth_blockNumber | sed 's/^0x//')))
  if [ "$HEAD_NOW" -gt "$HEAD_BEFORE" ]; then PRODUCING=1; break; fi
  sleep 2
done
if [ "$PRODUCING" = "1" ]; then
  echo "      head advanced to block $HEAD_NOW; the chain is producing"
else
  # An on-demand node (hardhat, anvil in interval-less mode) only mines when it
  # receives a transaction, so a flat head is not necessarily a fault. Say so
  # rather than blocking a run that would have worked.
  echo "      head is flat at block $HEAD_BEFORE after 60 s."
  echo "      If this endpoint mines on demand, that is expected and the run continues."
  echo "      If it is a QBFT validator set, quorum is not formed: check the other nodes with"
  echo "        docker compose -f $BESU_COMPOSE logs --tail 50"
fi

# Report what actually answered instead of asserting the topology. Attaching to
# an arbitrary endpoint and printing "QBFT, 4 validators" put a claim on screen
# that this script had not checked.
CLIENT_VERSION="$(rpc_call web3_clientVersion | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
[ -n "$CLIENT_VERSION" ] && echo "      client: $CLIENT_VERSION"
# `grep` exits 1 when it matches nothing, and under `set -o pipefail` that
# fails the whole substitution and aborts the script. A node that does not
# implement the QBFT namespace is the normal case here, not an error.
VALIDATOR_COUNT="$( { rpc_call qbft_getValidatorsByBlockNumber '["latest"]' \
  | grep -o '0x[0-9a-fA-F]\{40\}' || true; } | wc -l | tr -d ' ')"
if [ "${VALIDATOR_COUNT:-0}" -gt 0 ]; then
  echo "      consensus: QBFT with $VALIDATOR_COUNT validators (reported by the node)"
elif [ "$ATTACHED_ENDPOINT" = "1" ]; then
  echo "      consensus: not reported by this endpoint; it is NOT known to be the QBFT validator set"
fi
if [ "$STARTED_CHAIN" = "1" ]; then
  echo "      this script started the chain; stop it with:"
  echo "        docker compose -f $BESU_COMPOSE down -v"
fi

# A chain that is not the in-process development node needs the explicit
# public-transaction posture and locally held signers: Besu exposes no unlocked
# accounts, so the signers are derived from the mnemonic.
# ------------------------------------------------------- window sizing ------
# A phase closes on wall-clock time, but its transactions are SEQUENTIAL and
# each needs its own block. Sizing rule, per phase:
#     window > (sequential transactions) x (inclusion time) + margin
# Inclusion time is at least one block period and in practice a few, because
# the harness waits for each receipt before sending the next transaction.
# Measured here rather than assumed: the same script has to work on a 2-second
# QBFT chain and on a node that mines on demand.
BLOCK_PERIOD=2
T1="$(rpc_result eth_blockNumber)"
sleep 6
T2="$(rpc_result eth_blockNumber)"
if [ -n "$T1" ] && [ -n "$T2" ]; then
  D=$(( $((0x0${T2#0x})) - $((0x0${T1#0x})) ))
  [ "$D" -gt 0 ] && BLOCK_PERIOD=$(( (6 + D - 1) / D ))
fi
# 3 auditors commit, then 3 opening participants open, sequentially; the
# challenge phase carries the challenge plus its bond transaction. The factors
# below are those transaction counts times a 4-block inclusion allowance.
: "${DEMO_COMMIT_WINDOW_SECONDS:=$(( BLOCK_PERIOD * 24 < 45 ? 45 : BLOCK_PERIOD * 24 ))}"
: "${DEMO_OPEN_WINDOW_SECONDS:=$(( BLOCK_PERIOD * 24 < 45 ? 45 : BLOCK_PERIOD * 24 ))}"
: "${DEMO_CHALLENGE_WINDOW_SECONDS:=$(( BLOCK_PERIOD * 16 < 30 ? 30 : BLOCK_PERIOD * 16 ))}"
# Disclosure publishes 32 leaves in batches of 8: 4 sequential batches. The
# floor stays at 180 s anyway, because the phase also carries the fixed cost of
# opening the phase and waiting for finality, which does not shrink with N.
: "${DEMO_DISCLOSURE_WINDOW_SECONDS:=$(( BLOCK_PERIOD * 4 * 6 < 180 ? 180 : BLOCK_PERIOD * 4 * 6 ))}"
echo "      block period ~${BLOCK_PERIOD}s; windows: commit ${DEMO_COMMIT_WINDOW_SECONDS}s,"
echo "      open ${DEMO_OPEN_WINDOW_SECONDS}s, challenge ${DEMO_CHALLENGE_WINDOW_SECONDS}s, disclosure ${DEMO_DISCLOSURE_WINDOW_SECONDS}s"
export DEMO_COMMIT_WINDOW_SECONDS DEMO_OPEN_WINDOW_SECONDS
export DEMO_CHALLENGE_WINDOW_SECONDS DEMO_DISCLOSURE_WINDOW_SECONDS

export FHE_POD_NETWORK="${FHE_POD_NETWORK:-vcfhe}"
export VCFHE_RPC_URL="$RPC_URL"
export VCFHE_EXPECTED_CHAIN_ID="$CHAIN_ID"
export VCFHE_MNEMONIC="$MNEMONIC"
export VCFHE_ACCOUNT_COUNT="${VCFHE_ACCOUNT_COUNT:-40}"
export DEMO_COMMIT_WINDOW_SECONDS
export DEMO_OPEN_WINDOW_SECONDS
export DEMO_CHALLENGE_WINDOW_SECONDS
export DEMO_DISCLOSURE_WINDOW_SECONDS

# ---------------------------------------------------------- 2. dependencies --
say "2/8" "DEPENDENCIES — node modules for fhe-pod"
if [ ! -d "$REPO_ROOT/fhe-pod/node_modules" ]; then
  echo "      not installed yet; installing (first run only)"
  ( cd "$REPO_ROOT/fhe-pod" && { npm ci || npm install; } )
else
  echo "      already present"
fi

# ------------------------------------------------------------- 3. contracts --
say "3/8" "CONTRACTS — compiling the dispute game and the objective leaf verifier"
( cd "$REPO_ROOT/fhe-pod" && npm run compile:contracts )

# --------------------------------------------------------------- 4. signers --
say "4/8" "SIGNERS — funding the protocol roles on the validator network"
echo "      operator, challenger, auditor pool and opening pool are ordinary accounts"
( cd "$REPO_ROOT/fhe-pod" && npm run network:fund-signers ) || {
  echo "      ! funding step reported a problem; continuing, the demo will fail loudly" >&2
  echo "        if a role cannot pay for its stake." >&2
}

# ------------------------------------------------------- 5,6,7. the demo run --
# Inline narration. Phases 5, 6 and 7 announce what is about to happen; with
# NARRATE_INLINE=1 (the default) each announcement is followed by the acts of
# the narrator that show the actual values that stage produces, so the audience
# sees the uint64 registers, then the leaves, then the bisection ladder, rather
# than a summary after the fact. Set NARRATE_INLINE=0 for the terse announcements.
NARRATE_INLINE="${NARRATE_INLINE:-1}"
narrate_acts() {  # narrate_acts <spec>
  # --bare: the banner and the disclaimer are printed once by this script, not
  # once per phase. Written as two explicit branches rather than with a local
  # array, because `local arr=()` is not portable to the bash 3.2 that macOS
  # ships. A narration fault must never abort a live run, hence the `||` arm.
  if [ "$NARRATE_LEAVES" = "1" ]; then
    node "$HERE/narrate-anatel-simplified.mjs" --bare --leaves --acts "$1" \
      || echo "      ! narration failed; the run continues" >&2
  else
    node "$HERE/narrate-anatel-simplified.mjs" --bare --acts "$1" \
      || echo "      ! narration failed; the run continues" >&2
  fi
}

say "5/8" "EXPRESSION — lowering the RQUAL formula to the 15-operation micro-ISA"
if [ "$NARRATE_INLINE" = "1" ]; then
  narrate_acts 1-5
else
  echo "      IQS and IQP enter as single encrypted indicators, already in permille"
  echo "      IR  = 1000 * A_P / B_P, inverted with MIN before SUB so it cannot underflow"
  echo "      F(.) = how many declared band edges each indicator exceeds (three here)"
  echo "      S = F(IQS) + F(IQP) + F(IR)  ->  seal index, the ONLY value released"
fi

say "6/8" "ENCRYPTION — executing the trace over TFHE ciphertexts (cached after the first run)"
if [ "$NARRATE_INLINE" = "1" ]; then
  narrate_acts 6
else
  echo "      every operand handle registered on chain is keccak256 of a serialized"
  echo "      FheUint64 ciphertext; both the honest and the corrupted variant are executed,"
  echo "      and every leaf is decrypted and checked against the claimed value"
fi

say "7/8" "DISPUTE — commit, audit, challenge, disclose, bisect, resolve one leaf, slash"
echo "      windows: commit ${DEMO_COMMIT_WINDOW_SECONDS}s, open ${DEMO_OPEN_WINDOW_SECONDS}s, challenge ${DEMO_CHALLENGE_WINDOW_SECONDS}s, disclosure ${DEMO_DISCLOSURE_WINDOW_SECONDS}s"
if [ "$NARRATE_INLINE" = "1" ]; then
  # The bisection ladder is fixed by the trace size and the corrupted leaf, so
  # it can be shown BEFORE the dispute runs: the audience then watches the live
  # rounds land on the intervals already on screen.
  narrate_acts 7
else
  echo "      the dishonest operator inflates exactly the leaf that produces its own seal"
fi

cd "$REPO_ROOT/fhe-pod"
if [ "$HAVE_DEMO_ARGS" = "1" ]; then
  npm run demo:anatel-simplified -- "${DEMO_ARGS[@]}"
else
  npm run demo:anatel-simplified
fi

say "8/8" "RECORD — what was written"
echo "      fhe-pod/artifacts/runs/anatel-rqual-simplified-demo-*/          trace, receipts, dispute result"
echo "      fhe-pod/artifacts/evaluations/anatel-rqual-simplified-demo/     the run record, incl. every"
echo "                                                          transaction hash, block and gas"
echo
banner "ANATEL RQUAL simplified demonstration complete"
echo
echo "  Remember to say it plainly: the seal above is NOT an official ANATEL result."
echo "  Structure from Res. 717/2019; every number a declared deployment parameter."
echo
