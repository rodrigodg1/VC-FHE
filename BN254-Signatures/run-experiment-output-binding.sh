#!/bin/bash
# ============================================================================
# Output-bound multi-key linear verification: metrics pipeline
# ============================================================================
# Produces every metric the linear path reports:
#
#   1) Off-chain multi-key metrics -> ../output-binding-lhs/metrics_output_binding.csv
#      (per-owner keygen, commitment P(c_i), context-bound signing, per-record
#       admission, accumulator fold, O(1) result check, (N+1)-pairing aggregate
#       certificate, proof sizes; swept over dataset size N and dimension D)
#
#   2) On-chain gas                -> mklhs_tfhe_gas_results.csv
#      (MKLHS-Verification.sol with per-owner keys: deployment O(N), key
#       registration and admission per owner, submitResultBound O(1); honest
#       ACCEPT, output-substitution REJECT and wrong-key REJECT on every row)
#      plus mklhs_maptogroup_fit.txt, the MapToGroup trial-count sensitivity.
#
#   3) Plots + summary             -> ../output-binding-lhs/plots_output_binding/
#
# Cost model of the deployed linear path:
#   * FHE layer: leveled LWE, coordinate-wise addition, no bootstrap. Exact
#     decryption holds only inside the message and noise budgets of the
#     correctness lemma; the real-TFHE binary enforces that guard.
#   * Authentication (the cost of binding the output): the owner computes the
#     commitment P(c_i), O(D) group operations, then one MapToGroup and one
#     scalar multiplication, both constant in D.
#   * On-chain: one 2-pairing check per record at admission, and a pairing-free
#     O(1) result check that is independent of N and D.
#   * Gas is measured under the hardfork pinned in hardhat.config.js, which is
#     the one the validator genesis activates (Berlin and London at block zero).
#
# The evaluation pipeline requires the REAL-TFHE path. Set OB_ALLOW_MIRROR=1 only
# for algebraic development checks on a host that cannot compile tfhe-rs; mirror
# results must not be reported as end-to-end TFHE evidence.
#
# Usage:
#   ./run-experiment-output-binding.sh
# Env overrides:
#   OB_SIZES="10 50 100 200"  OB_DIMS="5 64 256 1024"  OB_REPEATS=10
#   OB_HARDHAT_NETWORK=vcfhe VCFHE_RPC_URL=<rpc> VCFHE_PRIVATE_KEYS=<csv>
#     deploys and measures the linear contracts on the configured EVM network.
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "${VCFHE_LEGACY_EVALUATION:-0}" != "1" ]; then
  exec "$HERE/../run-linear.sh" "$@"
fi
CRATE_DIR="$HERE/../output-binding-lhs"

SIZES="${OB_SIZES:-10 50 100 200}"
DIMS="${OB_DIMS:-5 64 256 1024}"
REPEATS="${OB_REPEATS:-10}"
ALLOW_MIRROR="${OB_ALLOW_MIRROR:-0}"
HARDHAT_NETWORK_ARGS=()
if [ -n "${OB_HARDHAT_NETWORK:-}" ]; then
  HARDHAT_NETWORK_ARGS=(--network "$OB_HARDHAT_NETWORK")
fi
# Expanded through the "${arr[@]+...}" form below: under `set -u`, bash 3.2
# (the /bin/bash that macOS ships) treats "${arr[@]}" on an empty array as an
# unbound variable and aborts the script. The form is a no-op on newer bash.

echo "=========================================================="
echo "Output-binding metrics pipeline (new version)"
echo "Sizes: [$SIZES]  Dims: [$DIMS]  Repeats: $REPEATS"
echo "=========================================================="

# ---- 0. Build mirror crate + compile contract ----
( cd "$CRATE_DIR" && cargo build --release )
npm ci
npm run compile

# ---- 1. Off-chain authenticator metrics (O(D) sign, O(1) verify) ----
echo "[1/4] Off-chain authenticator metrics  (cost of W2 and W3 vs N and D)..."
( cd "$CRATE_DIR" && \
  OB_SIZES="$SIZES" OB_DIMS="$DIMS" OB_REPEATS="$REPEATS" \
  cargo run --release -- bench metrics_output_binding.csv )

# ---- 2. REAL-TFHE end-to-end path (leveled LWE) + payload emission ----
# The self-validating demo checks SUM and SUB with exact decryption and the
# output-substitution rejection. The emission writes the per-owner records the
# on-chain stage measures. Both use real TFHE-LWE ciphertexts; the emission is
# seeded, so the payload and therefore the gas table are reproducible.
echo "[2/4] Real-TFHE path: W2 encrypt/commit/sign -> W3 aggregate -> W5 decrypt,"
echo "      then emit the seeded multi-key payload the on-chain stage consumes..."
PROOF_SRC=""
if cargo build --release --bin output_binding_tfhe >/dev/null 2>&1; then
  cargo run --release --bin output_binding_tfhe
  cargo run --release --bin output_binding_tfhe -- \
    emit-onchain-mk "$HERE/onchain_proofs_tfhe_mk.json" $SIZES
  PROOF_SRC="$HERE/onchain_proofs_tfhe_mk.json"
else
  if [ "$ALLOW_MIRROR" != "1" ]; then
    echo "ERROR: real TFHE output-binding binary is unavailable." >&2
    echo "Set OB_ALLOW_MIRROR=1 only for non-evaluation algebraic checks." >&2
    exit 1
  fi
  echo "  WARNING: TFHE binary unavailable; emitting the field-level mirror payload."
  echo "  These rows are a wiring regression, NOT end-to-end TFHE evidence."
  ( cd "$CRATE_DIR" && cargo run --release -- \
      emit-onchain-mk "$HERE/onchain_proofs_mirror_mk.json" $SIZES )
  PROOF_SRC="$HERE/onchain_proofs_mirror_mk.json"
fi

# ---- 2b. Per-phase wall-clock timings, real libraries ----
# Measured in the SAME binary that drives tfhe-rs, so the reported encryption,
# commitment, signature, admission and decryption times are the ones the
# protocol performs. This feeds the two timing tables of section 01; without it
# the experiment-artifact builder skips that section entirely.
echo "[2b/4] Per-phase timings: W2 keygen/encrypt/commit/sign, W3 aggregate,"
echo "       W4 result check vs the (N+1)-pairing baseline, W5 consumer check..."
cargo run --release --bin output_binding_tfhe -- \
  bench-timings "$HERE/timings_linear.csv" $SIZES --repeats "${OB_TIMING_REPEATS:-5}"

# ---- 3. On-chain gas (curator-free multi-key contract) ----
# Deploys MKLHS-Verification.sol with per-owner keys and measures deployment,
# key registration, record admission and result submission, asserting honest
# acceptance, output-substitution rejection and the wrong-key rejection on every
# row. The hardfork is pinned in hardhat.config.js to the rules the validator
# genesis activates, so these are the gas values the evaluated chain charges.
echo "[3/4] On-chain: W1 setup/assign -> W2 admit -> W4 verify -> W5 consumer check"
echo "      (MKLHS-Verification.sol on the configured network)..."
PAYLOAD="$PROOF_SRC" CSV_OUT="$HERE/mklhs_tfhe_gas_results.csv" \
  npx hardhat run scripts/mklhs_tfhe_onchain.js "${HARDHAT_NETWORK_ARGS[@]+${HARDHAT_NETWORK_ARGS[@]}}"

# MapToGroup trial-count sensitivity of the admission cost, reported alongside
# the table. N=120 gives the 119-admission fit quoted in the evaluation.
N=120 npx hardhat run scripts/mklhs_maptogroup_gas.js \
  "${HARDHAT_NETWORK_ARGS[@]+${HARDHAT_NETWORK_ARGS[@]}}" \
  | tee "$HERE/mklhs_maptogroup_fit.txt"

# ---- 4. Plots + summary ----
echo "[4/4] Plots + summary..."
if ! python3 -c 'import matplotlib' >/dev/null 2>&1; then
  echo "Plotting skipped (need python3 + matplotlib)."
else
  OB_ONCHAIN_CSV="$HERE/mklhs_tfhe_gas_results.csv" \
    python3 "$CRATE_DIR/analyze_output_binding.py"
fi

echo "=========================================================="
echo "Done.  (on-chain proofs: $PROOF_SRC)"
echo "  off-chain: $CRATE_DIR/metrics_output_binding.csv"
echo "  on-chain:  $HERE/mklhs_tfhe_gas_results.csv"
echo "  map fit:   $HERE/mklhs_maptogroup_fit.txt"
echo "  timings:   $HERE/timings_linear.csv"
echo "  plots:     $CRATE_DIR/plots_output_binding/"
echo "=========================================================="
