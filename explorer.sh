#!/usr/bin/env bash
# ============================================================================
#  VC-FHE — start the read-only dashboard for the QBFT network
# ============================================================================
#  One container, optional and read-only:
#
#    dashboard  http://localhost:8081   chain status; the linear path with its
#                                       output-binding records; the dispute
#                                       game with sampling, bisection, leaf
#                                       check, verdict and slashing; blocks
#                                       and transactions; and a search that
#                                       resolves a transaction, block or
#                                       address with its logs decoded
#
#  It runs under the compose profile "explorer", so it never starts with the
#  chain and never interferes with run-poc.sh. It holds no key and sends
#  no transaction: it issues eth_*, net_* and qbft_* reads only.
#
#  Usage:  ./explorer.sh up | down | status | logs
# ----------------------------------------------------------------------------
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

RPC_URL="${RPC_URL:-http://127.0.0.1:8550}"
ACTION="${1:-up}"

if [ -t 1 ]; then B=$'\033[1m'; DIM=$'\033[2m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RST=$'\033[0m'
else B=""; DIM=""; GRN=""; YLW=""; RST=""; fi

chain_up() {
  curl -s -m 5 -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
    "$RPC_URL" 2>/dev/null | grep -q result
}

case "$ACTION" in
  up)
    if ! chain_up; then
      echo "${YLW}   ! no chain answering at $RPC_URL${RST}"
      echo "     Start it first:  docker compose up -d node1 node2 node3 node4"
      echo "     (the dashboard only reads; it does not start the chain)"
    fi
    docker compose --profile explorer up -d explorer-dashboard
    echo
    echo "${B} protocol dashboard ${RST} http://localhost:8081"
    echo "${DIM}   chain status, linear path (LHS output binding), dispute timelines,"
    echo "   blocks and transactions, and search by hash, block or address;"
    echo "   rescans the chain every 10 s${RST}"
    echo
    echo "${DIM} stop it with: ./explorer.sh down${RST}"
    ;;
  down)
    docker compose --profile explorer stop explorer-dashboard
    docker compose --profile explorer rm -f explorer-dashboard
    echo "${GRN}   dashboard stopped; the chain was not touched${RST}"
    ;;
  status)
    docker compose --profile explorer ps explorer-dashboard
    chain_up && echo "${GRN}   chain reachable at $RPC_URL${RST}" \
             || echo "${YLW}   chain NOT reachable at $RPC_URL${RST}"
    ;;
  logs)
    docker compose --profile explorer logs -f --tail=50 explorer-dashboard
    ;;
  *)
    echo "usage: ./explorer.sh [up|down|status|logs]" >&2
    exit 2 ;;
esac
