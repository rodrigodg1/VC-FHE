#!/usr/bin/env bash
# ============================================================================
#  VC-FHE  —  MINIMAL ARITHMETIC TEACHING EXAMPLE
# ============================================================================
#  One command. The whole protocol on the shortest trace it can run, for one
#  arithmetic expression and nothing else:
#
#      total = x + y * z
#
#  Standard precedence fixes the order, and the order of the leaves is what the
#  protocol commits to:
#
#      leaf 0   MUL   y * z              both operands encrypted
#      leaf 1   ADD   x + (y*z)          = total, the only released value
#
#  Two leaves -- already a power of two, so nothing is padded -- one bisection
#  round, two of the fifteen operations. Every operand is a ciphertext.
#  chain up (4-validator Besu QBFT) -> lower the expression -> execute
#  it over TFHE ciphertexts -> commit -> auditors -> a challenge -> full trace
#  disclosure -> bisection -> homomorphic leaf decision attested by t+1
#  signatures -> slashing.
#
#  WHAT THIS DEMONSTRATES
#  ----------------------
#  The PROCESS, end to end, on a computation small enough to hold in your head.
#  It is the example to read first, and the one to project when the question is
#  "what does this protocol actually do to a calculation".
#
#  WHAT IT DOES NOT DEMONSTRATE
#  ----------------------------
#  Anything about accuracy or scale. The three values are ARBITRARY: there is no
#  dataset, no measurement and no regulation behind any of them. Two leaves say
#  nothing about the cost of large traces, and this example is NOT part of the
#  implementation's evaluated workload set.
#
#  Three real parts of the instruction set are absent, and each costs a lesson:
#    - DIV, and with it the PUBLIC SCALAR rule (4 of the 15 opcodes take a
#      cleartext right operand). Here EVERY operand is encrypted;
#    - integer TRUNCATION, which needs a division to be visible;
#    - SUB and its underflow guard.
#  Padding is likewise never exercised: two leaves is already a power of two.
#  For a real formula see
#  ../../Anatel/anatel-rqual-simplificado/ (28 leaves) and ../../Anatel/anatel-rqual/ (89 leaves);
#  for evidence about scale see the eleven evaluated workloads.
#
#  Outputs:
#     fhe-pod/artifacts/runs/arithmetic-demo-<stamp>/     trace + receipts
#     fhe-pod/artifacts/evaluations/arithmetic-demo/      the run record
#
# ----------------------------------------------------------------------------
#  KNOBS
# ----------------------------------------------------------------------------
#  NARRATE=1   nine-act narration of what each stage of the protocol does to
#              this calculation, drawing both the expression tree and the Merkle
#              tree the bisection walks. Contacts no chain, spawns nothing,
#              writes nothing. This is the mode to project.
#              NARRATE_PAUSE=1   wait for Enter between acts
#              NARRATE_SLOW=<s>  auto-advance every <s> seconds
#              NARRATE_ACT=<n>   print only these acts: 5, or 1-5, or 0,2,5
#                                (nine acts, 0 to 8)
#  DRY_RUN=1   build, verify and print the trace and the reference values;
#              contact no chain, spawn nothing, write nothing.
#  NARRATE_INLINE=0
#              turn OFF the narration the FULL run prints inside phases 5, 6
#              and 7. On by default.
#
#  RPC_URL     JSON-RPC endpoint. default http://127.0.0.1:8550
#              If nothing answers there and the endpoint is LOCAL, this script
#              brings up the 4-validator Besu QBFT network itself. A remote
#              endpoint that is down is an error: nothing runnable here fixes it.
#  ATTACH_ONLY=1   never start a chain; stop instead of running docker compose.
#  CHAIN_ID    expected chain id. default 46853 (the 4-validator QBFT net)
#  MNEMONIC    funding mnemonic. default: the genesis dev mnemonic
#  MANIPULATED_LEAF_INDEX=<n>  corrupt leaf n instead of the ADD that yields total
#  REFRESH_FHE=1   re-run the TFHE executor even when a manifest already covers
#              this exact trace
#
#  The four window knobs below are OVERRIDES. Unset, they are computed from the
#  block period this script MEASURES at the endpoint, with floors of 45 s, 45 s,
#  30 s and 180 s. Eight seconds looked fine on an in-process EVM, where a
#  transaction mines the instant it is sent, and failed on the QBFT network with
#  WrongPhase(): each auditor's submitAudit needs its own block.
#  DEMO_COMMIT_WINDOW_SECONDS       auditor commit window     measured, floor  45
#  DEMO_OPEN_WINDOW_SECONDS         auditor reveal window     measured, floor  45
#  DEMO_CHALLENGE_WINDOW_SECONDS    challenge window          measured, floor  30
#  DEMO_DISCLOSURE_WINDOW_SECONDS   disclosure window         measured, floor 180
#     Sizing rule: a trace of N leaves published k at a time needs ceil(N/k)
#     STRICTLY SEQUENTIAL batches, so the window must exceed that many block
#     inclusions plus a finality margin. This trace is 2 leaves, so disclosure
#     needs a single batch; the 180 s floor stays anyway, because the phase also
#     carries the fixed cost of opening it and waiting for finality.
#
#  ENCRYPTED EXECUTION. Every operand handle registered on chain is keccak256 of
#  a serialized TFHE ciphertext, produced by executing this trace over FheUint64
#  values with tfhe-rs. Both variants, honest and corrupted, are executed, and
#  every leaf is decrypted and compared against the value the lowering claims.
#  The manifest is cached under fhe-pod/artifacts/fhe/arithmetic-demo/, so the
#  slow step runs once. 4 leaves under encryption take seconds, but the FIRST
#  cargo build of tfhe-rs takes minutes on its own: run it once before a live
#  demonstration.
#
#  Examples:
#     examples/exemplo-aritmetico/run-arithmetic-demo.sh                    # start the chain, run it
#     NARRATE=1 examples/exemplo-aritmetico/run-arithmetic-demo.sh           # narrate, no chain at all
#     NARRATE=1 NARRATE_PAUSE=1 examples/exemplo-aritmetico/run-arithmetic-demo.sh   # one act per keypress
#     DRY_RUN=1 examples/exemplo-aritmetico/run-arithmetic-demo.sh           # print the trace, no chain
#     RPC_URL=http://127.0.0.1:8550 examples/exemplo-aritmetico/run-arithmetic-demo.sh   # attach
# ----------------------------------------------------------------------------
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
NARRATE_ACT="${NARRATE_ACT:-}"
REFRESH_FHE="${REFRESH_FHE:-0}"
MANIPULATED_LEAF_INDEX="${MANIPULATED_LEAF_INDEX:-}"
# ----------------------------------------------------------------------------
set -euo pipefail

# Resolve the repository root two levels above this example directory.
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
# Keep the machine awake. On macOS, idle sleep freezes Docker's VM, the
# validators stop producing blocks, and every in-flight receipt wait fails on
# wake with a wall-clock timeout that looks like a chain fault but is not one.
# ---------------------------------------------------------------------------
if [ "$(uname -s)" = "Darwin" ] && [ -z "${VCFHE_CAFFEINATED:-}" ] \
   && command -v caffeinate >/dev/null 2>&1; then
  export VCFHE_CAFFEINATED=1
  exec caffeinate -ims "$0" "$@"
fi

banner "VC-FHE  |  minimal arithmetic teaching example  |  total = x + y * z"
echo
echo "  The three values are ARBITRARY, chosen to explain the process. Nothing is measured,"
echo "  nothing is regulated, and this example is not part of the evaluation's evaluation."
echo "  Two leaves, already a power of two; one bisection round; every operand encrypted."

# Expanded through the "${arr[@]+...}" form below: under `set -u`, bash 3.2 (the
# /bin/bash macOS ships) treats "${arr[@]}" on an empty array as an unbound
# variable and aborts. HAVE_DEMO_ARGS exists for the same reason on the npm
# side: `npm run <script> --` with nothing after the separator is not worth
# relying on, so the empty case runs a plain command.
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
# Needs no chain, no Docker and no installed dependency tree, so it is the mode
# to fall back on if anything else fails during a live meeting.
if [ "$NARRATE" = "1" ]; then
  NARRATE_ARGS=()
  [ "$NARRATE_PAUSE" = "1" ] && NARRATE_ARGS+=(--pause)
  [ -n "$NARRATE_SLOW" ] && NARRATE_ARGS+=(--slow "$NARRATE_SLOW")
  [ -n "$NARRATE_ACT" ] && NARRATE_ARGS+=(--act "$NARRATE_ACT")
  say "0/8" "NARRATION — what each stage of the protocol does to this calculation."
  # MANIPULATED_LEAF_INDEX is exported for the narrator too: act 7 DRAWS the
  # bisection path, and a narration that ignored the override would show the
  # search descending into a branch the real run does not corrupt.
  MANIPULATED_LEAF_INDEX="$MANIPULATED_LEAF_INDEX" \
    node "$HERE/narrate-arithmetic-demo.mjs" ${NARRATE_ARGS[@]+"${NARRATE_ARGS[@]}"}
  echo
  banner "Narration complete. No chain was contacted and nothing was written."
  exit 0
fi

# --------------------------------------------------------------- 0. dry run --
if [ "$DRY_RUN" = "1" ]; then
  say "0/8" "DRY RUN — building and printing the trace only. No chain is contacted."
  cd "$REPO_ROOT/fhe-pod"
  node "$HERE/run-arithmetic-demo.mjs" --dry-run ${DEMO_ARGS[@]+"${DEMO_ARGS[@]}"}
  echo
  banner "Dry run complete. Nothing was spawned and nothing was written."
  exit 0
fi

# ----------------------------------------------------------------- 1. chain --
STARTED_CHAIN=0
ATTACHED_ENDPOINT=0

rpc_call() {  # rpc_call <method> [params-json]
  curl -s -m 5 -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" \
    "$RPC_URL" 2>/dev/null || true
}
rpc_result() { rpc_call "$1" "${2:-[]}" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'; }

start_besu_network() {
  if [ ! -f "$BESU_COMPOSE" ]; then
    echo "ERROR: $BESU_COMPOSE not found; cannot self-start the chain." >&2
    echo "       Start a chain yourself and re-run with RPC_URL=<endpoint>." >&2
    exit 1
  fi
  # Check the daemon before invoking compose: `docker compose up` on a host
  # without a running daemon fails with a message about the socket, which reads
  # like a bug in this script rather than a missing prerequisite.
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
# finds nothing listening exits 7 and would abort the script AT THIS ASSIGNMENT,
# so the diagnostic below would never print.
CHAIN_ID_HEX="$(curl -s -m 5 -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
  "$RPC_URL" 2>/dev/null | sed -n 's/.*"result":"\([^"]*\)".*/\1/p' || true)"
if [ -z "$CHAIN_ID_HEX" ]; then
  echo "ERROR: no JSON-RPC endpoint answered at $RPC_URL" >&2
  echo "       Start the 4-validator QBFT network first:" >&2
  echo "         docker compose -f $BESU_COMPOSE up -d" >&2
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
# transaction would then sit in the pool until a timeout.
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
  # An on-demand node (hardhat, anvil without an interval) only mines when it
  # receives a transaction, so a flat head is not necessarily a fault.
  echo "      head is flat at block $HEAD_BEFORE after 60 s."
  echo "      If this endpoint mines on demand, that is expected and the run continues."
  echo "      If it is a QBFT validator set, quorum is not formed: check the other nodes with"
  echo "        docker compose -f $BESU_COMPOSE logs --tail 50"
fi

# Report what actually answered instead of asserting the topology.
CLIENT_VERSION="$(rpc_call web3_clientVersion | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
[ -n "$CLIENT_VERSION" ] && echo "      client: $CLIENT_VERSION"
# `grep` exits 1 when it matches nothing, and under `set -o pipefail` that fails
# the whole substitution. A node without the QBFT namespace is the normal case.
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

# ------------------------------------------------------- window sizing ------
# A phase closes on wall-clock time, but its transactions are SEQUENTIAL and each
# needs its own block:
#     window > (sequential transactions) x (inclusion time) + margin
# Measured rather than assumed: the same script has to work on a 2-second QBFT
# chain and on a node that mines on demand.
BLOCK_PERIOD=2
T1="$(rpc_result eth_blockNumber)"
sleep 6
T2="$(rpc_result eth_blockNumber)"
if [ -n "$T1" ] && [ -n "$T2" ]; then
  D=$(( $((0x0${T2#0x})) - $((0x0${T1#0x})) ))
  [ "$D" -gt 0 ] && BLOCK_PERIOD=$(( (6 + D - 1) / D ))
fi
# The cost of ONE transaction, end to end: send -> inclusion -> receipt observed.
#
# This is the quantity the windows actually have to be sized against, and it is
# NOT the block period. MEASURED on this QBFT network: consecutive submitAudit
# transactions landed in blocks 968, 972, 976 and 980 -- four block periods each,
# because the receipt is only observed some blocks after the send, not one.
#
# The previous formula multiplied the BLOCK PERIOD by a flat 24, which is only
# correct when a transaction costs one block. At four blocks per transaction it
# understates the open phase by 4x, and the phase then expires mid-sequence with
# a revert on openVerdict. Observed exactly that: the open deadline was
# 1786975171 and the sixth opening landed at 1786975173 -- two seconds late,
# after the machine slowed down under load (the same run's homomorphic MUL went
# from 2986 ms to 5111 ms). A window with no margin is a race against host load.
TX_COST=$(( BLOCK_PERIOD * 4 ))
[ "$TX_COST" -lt 8 ] && TX_COST=8

# Sequential transactions each phase carries, read off the protocol's shape:
#   commit    one submitAudit per assigned auditor                      = 3
#   open      one openVerdict per (auditor, opening participant) pair   = 3 x 2 = 6
#             ^ the old comment said "3 opening participants open", which
#               undercounted this phase by half.
#   challenge the challenge transaction plus its diligence proof        = 2
# SAFETY doubles the result: these are the phases that failed, and a demo that
# waits an extra minute is strictly better than one that dies at minute eight.
COMMIT_TXS=3
OPEN_TXS=6
CHALLENGE_TXS=2
SAFETY=2
: "${DEMO_COMMIT_WINDOW_SECONDS:=$(( COMMIT_TXS * TX_COST * SAFETY < 45 ? 45 : COMMIT_TXS * TX_COST * SAFETY ))}"
: "${DEMO_OPEN_WINDOW_SECONDS:=$(( OPEN_TXS * TX_COST * SAFETY < 45 ? 45 : OPEN_TXS * TX_COST * SAFETY ))}"
: "${DEMO_CHALLENGE_WINDOW_SECONDS:=$(( CHALLENGE_TXS * TX_COST * SAFETY < 30 ? 30 : CHALLENGE_TXS * TX_COST * SAFETY ))}"
# Eight leaves publish in a single batch, so disclosure is dominated by the fixed
# cost of opening the phase and waiting for finality, which does not shrink with N.
: "${DEMO_DISCLOSURE_WINDOW_SECONDS:=180}"
echo "      block period ~${BLOCK_PERIOD}s; windows: commit ${DEMO_COMMIT_WINDOW_SECONDS}s,"
echo "      open ${DEMO_OPEN_WINDOW_SECONDS}s, challenge ${DEMO_CHALLENGE_WINDOW_SECONDS}s, disclosure ${DEMO_DISCLOSURE_WINDOW_SECONDS}s"

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
NARRATE_INLINE="${NARRATE_INLINE:-1}"
narrate_acts() {  # narrate_acts <spec>
  # --bare: the banner is printed once by this script, not once per phase.
  # A narration fault must never abort a live run, hence the `||` arm.
  MANIPULATED_LEAF_INDEX="$MANIPULATED_LEAF_INDEX" \
    node "$HERE/narrate-arithmetic-demo.mjs" --bare --acts "$1" \
    || echo "      ! narration failed; the run continues" >&2
}

say "5/8" "EXPRESSION — lowering total = x + y * z to the 15-operation micro-ISA"
if [ "$NARRATE_INLINE" = "1" ]; then
  narrate_acts 1-4
else
  echo "      MUL, then ADD: standard precedence fixes the order"
  echo "      EVERY operand is encrypted; this expression has no public scalar"
  echo "      two leaves is already a power of two, so nothing is padded"
fi

say "6/8" "ENCRYPTION — executing the trace over TFHE ciphertexts (cached after the first run)"
if [ "$NARRATE_INLINE" = "1" ]; then
  narrate_acts 5
else
  echo "      every operand handle registered on chain is keccak256 of a serialized"
  echo "      FheUint64 ciphertext; both the honest and the corrupted variant are executed,"
  echo "      and every leaf is decrypted and checked against the claimed value"
fi

say "7/8" "DISPUTE — commit, audit, challenge, disclose, bisect, decide one leaf, slash"
echo "      windows: commit ${DEMO_COMMIT_WINDOW_SECONDS}s, open ${DEMO_OPEN_WINDOW_SECONDS}s, challenge ${DEMO_CHALLENGE_WINDOW_SECONDS}s, disclosure ${DEMO_DISCLOSURE_WINDOW_SECONDS}s"
if [ "$NARRATE_INLINE" = "1" ]; then
  # The bisection ladder is fixed by the trace size and the corrupted leaf, so it
  # can be shown BEFORE the dispute runs: the audience then watches the live
  # rounds land on the intervals already on screen.
  narrate_acts 6-8
else
  echo "      the dishonest operator claims a wrong total on exactly the leaf that produces it"
fi

cd "$REPO_ROOT/fhe-pod"
if [ "$HAVE_DEMO_ARGS" = "1" ]; then
  npm run demo:arithmetic -- "${DEMO_ARGS[@]}"
else
  npm run demo:arithmetic
fi

say "8/8" "RECORD — what was written"
echo "      fhe-pod/artifacts/runs/arithmetic-demo-*/         trace, receipts, dispute result"
echo "      fhe-pod/artifacts/evaluations/arithmetic-demo/    the run record, incl. every"
echo "                                                        transaction hash, block and gas"
echo
banner "Arithmetic teaching example complete"
echo
echo "  Say it plainly: the three values above are arbitrary, chosen to explain the process."
echo "  Two leaves are not evidence about scale."
echo
