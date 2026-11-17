#!/usr/bin/env python3
"""Generate the compact non-linear cost-and-time figure (fig_nonlinear_pipeline).

Produces the two-panel figure the evaluation references: how on-chain cost and
on-chain decision time grow with the micro-trace length N (task complexity):

  (a) verification gas versus N from the scaling experiment
      (challenged path, first-use optimistic path, complete disclosure,
      bisection, leaf resolution);
  (b) on-chain decision time versus N from the per-workload dispute runs
      (challenged-path transaction time, dispute wall clock from
      ``openChallenge`` to leaf settlement, flat leaf resolution).

Data sources (auto-detected, first match wins):
  artifacts/evaluations/latest_experiment_evaluation_verification_cost_scaling.csv
  artifacts/evaluations/latest_verification_cost_scaling.csv        (panel a)
  artifacts/evaluations/latest_experiment_evaluation_application_layer.csv
  artifacts/evaluations/latest_application_layer_evaluation.csv     (panel b)

Usage mirrors plot_experiment_figures.py:
  python scripts/plot_nonlinear_latency.py                 # auto-detect CSV
  python scripts/plot_nonlinear_latency.py --csv PATH
  python scripts/plot_nonlinear_latency.py --out-dir DIR
  python scripts/plot_nonlinear_latency.py --experiment-dir DIR
  python scripts/plot_nonlinear_latency.py --no-experiment-copy

Only the Python standard library and matplotlib are required.
"""

from __future__ import annotations

import argparse
import csv
import math
import shutil
import sys
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
EVAL_DIR = PROJECT_ROOT / "artifacts" / "evaluations"
DEFAULT_OUT_DIR = PROJECT_ROOT / "artifacts" / "figures"

CSV_CANDIDATES = [
    EVAL_DIR / "latest_experiment_evaluation_application_layer.csv",
    EVAL_DIR / "latest_application_layer_evaluation.csv",
]

SCALING_CSV_CANDIDATES = [
    EVAL_DIR / "latest_experiment_evaluation_verification_cost_scaling.csv",
    EVAL_DIR / "latest_verification_cost_scaling.csv",
]

BASENAME = "fig_nonlinear_pipeline"

WORKLOAD_LABELS = {
    "ml_linear_classifier": "Linear classifier",
    "stats_mean_variance": "Mean/variance",
    "stats_histogram_count": "Histogram",
    "ml_decision_rule": "Decision rule",
    "feature_bucket_score": "Bucket score",
    "stav360_mos_variance": "STAV360 MOS/var",
    "stav360_checkerboard_variance": "STAV360 checker",
    "stav360_poor_rating_sla": "STAV360 SLA",
    "qoe_mos_degradation_alarm": "MOS-BS alarm",
    "regulatory_qoe_compliance": "Regulatory compliance",
    "regional_qoe_compliance": "Regional compliance",
}




def _find_default_csv() -> Path:
    for candidate in CSV_CANDIDATES:
        if candidate.exists():
            return candidate
    tried = "\n  ".join(str(c) for c in CSV_CANDIDATES)
    sys.exit(
        "error: no application-layer CSV found. Run `npm run eval:applications` "
        "first.\nLooked for:\n  " + tried
    )


def _read_rows(csv_path: Path) -> list[dict]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        sys.exit(f"error: empty CSV: {csv_path}")
    return rows


LEAF_SETTLEMENT_LABELS = (
    "settleLeafViaAttestedDecision",
    "requestFhevmLeafResolution",
    "finalizeFhevmLeafResolution",
    "resolveLeafDispute",
)

_LEDGER_CACHE: dict[str, list[dict]] = {}


def _ledger_for(rows: list[dict]) -> list[dict]:
    """Per-transaction ledger of the run these rows came from, if archived."""
    evaluation_id = rows[0].get("evaluationId", "") if rows else ""
    if evaluation_id in _LEDGER_CACHE:
        return _LEDGER_CACHE[evaluation_id]
    found: list[dict] = []
    for name in (f"{evaluation_id}-transactions.csv",
                 "latest_application_layer_transactions.csv"):
        for base in (EVAL_DIR,):
            path = base / name
            if not path.exists():
                continue
            with path.open(newline="", encoding="utf-8") as handle:
                candidate = list(csv.DictReader(handle))
            if candidate and candidate[0].get("evaluationId") == evaluation_id:
                found = candidate
                break
        if found:
            break
    _LEDGER_CACHE[evaluation_id] = found
    return found


def _dispute_window_ms(row: dict, ledger: list[dict]) -> float | None:
    """Dispute duration: `openChallenge` to the settlement of the isolated leaf.

    Uses the harness measurement when the CSV carries it, and otherwise
    reconstructs it from the transaction ledger as the summed duration of the
    dispute transactions plus the measured homomorphic decision. See
    generate_experiment_tables.py, which applies the same rule to the table.
    """
    direct = str(row.get("disputeWallClockMs", "")).strip()
    if direct not in ("", "---"):
        return float(direct)
    txs = [t for t in ledger if t.get("workloadId") == row["workloadId"]
           and t.get("evaluationId") == row.get("evaluationId")
           and t.get("repetition", "") == row.get("repetition", "")]
    if not txs:
        return None
    labels = [str(t.get("label", "")) for t in txs]
    starts = [i for i, label in enumerate(labels) if label.startswith("openChallenge")]
    ends = [i for i, label in enumerate(labels) if label in LEAF_SETTLEMENT_LABELS]
    if not starts or not ends or max(ends) < min(starts):
        return None
    total = sum(float(t.get("durationMs") or 0) for t in txs[min(starts): max(ends) + 1])
    decision = str(row.get("leafDecisionOffchainMs", "")).strip()
    if decision not in ("", "---"):
        total += float(decision)
    return total


def _find_scaling_csv() -> Path | None:
    for candidate in SCALING_CSV_CANDIDATES:
        if candidate.exists():
            return candidate
    return None


def plot(rows: list[dict], out_dir: Path) -> Path:
    leaves = [int(r["leafCount"]) for r in rows]
    chal_tx_s = [float(r["localOnchainChallengedPathTxDurationMs"]) / 1000 for r in rows]
    leaf_tx_s = [float(r["localOnchainLeafResolutionTxDurationMs"]) / 1000 for r in rows]
    # The dispute series runs from `openChallenge` to the settlement of the
    # isolated leaf. `hardhatDisputeWallClockMs` times the whole run and is
    # used only for CSVs recorded before the dispute window was instrumented,
    # in which case the label says so.
    dispute_ms = [_dispute_window_ms(r, _ledger_for([r])) for r in rows]
    dispute_measured = all(v is not None for v in dispute_ms)
    wall_s = (
        [v / 1000 for v in dispute_ms] if dispute_measured
        else [float(r["hardhatDisputeWallClockMs"]) / 1000 for r in rows]
    )

    fig, (ax_a, ax_b) = plt.subplots(1, 2, figsize=(9.0, 3.3))

    # (a) verification gas versus N, from the scaling experiment.
    scaling_csv = _find_scaling_csv()
    if scaling_csv is None:
        sys.exit("error: no verification-cost scaling CSV found; run `npm run eval:costs`.")
    srows = sorted(_read_rows(scaling_csv), key=lambda r: int(r["leafCount"]))
    sn = [int(r["leafCount"]) for r in srows]
    series = [
        ("challengedPathGasUsed", "Complete challenged path", "#2c7fb8", "o", "-"),
        ("optimisticPathGasUsed", "First-use optimistic path", "#31a354", "s", "-"),
        ("traceDisclosureGasUsed", "Complete trace disclosure", "#c0392b", "^", "-"),
        ("bisectionGasUsed", "Bisection", "#d95f0e", "v", "-"),
        ("leafResolutionGasUsed", "ADD leaf resolution", "#756bb1", "D", "--"),
    ]
    for key, label, color, marker, style in series:
        ax_a.plot(sn, [float(r[key]) / 1e6 for r in srows], marker=marker,
                  linestyle=style, linewidth=1.6, markersize=4.5, color=color,
                  label=label)
    ax_a.set_xscale("log", base=2)
    ax_a.set_xticks(sn)
    ax_a.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_a.set_xlabel("Micro-trace length $N$ (leaves)")
    ax_a.set_ylabel("Verification gas (millions)")
    ax_a.set_title("(a) On-chain cost vs. trace length", fontsize=10)
    ax_a.grid(True, which="both", linestyle=":", alpha=0.5)
    ax_a.set_ylim(bottom=0)
    ax_a.legend(loc="upper left", fontsize=7, framealpha=0.9)

    # (b) on-chain decision time versus N, from the per-workload dispute runs.
    uniq_ns = sorted(set(leaves))

    def per_n_mean(values: list[float]) -> list[float]:
        return [
            sum(values[i] for i in range(len(rows)) if leaves[i] == n)
            / sum(1 for i in range(len(rows)) if leaves[i] == n)
            for n in uniq_ns
        ]

    sd = [statistics.stdev([wall_s[i] for i in range(len(rows)) if leaves[i] == n])
          if leaves.count(n) > 1 else 0 for n in uniq_ns]
    ax_b.errorbar(uniq_ns, per_n_mean(wall_s), yerr=sd, capsize=3, marker="s", linewidth=1.8,
              markersize=5, color="#31a354",
              label="Dispute mean ± SD" if dispute_measured else "Run wall clock")
    ax_b.plot(uniq_ns, per_n_mean(chal_tx_s), marker="o", linewidth=1.8,
              markersize=5, color="#2c7fb8", label="Challenged-path tx time")
    ax_b.plot(uniq_ns, per_n_mean(leaf_tx_s), marker="D", linewidth=1.4,
              markersize=5, linestyle="--", color="#756bb1",
              label="Leaf resolution")
    ax_b.set_xscale("log", base=2)
    ax_b.set_xticks(uniq_ns)
    ax_b.get_xaxis().set_major_formatter(plt.matplotlib.ticker.ScalarFormatter())
    ax_b.set_xlabel("Micro-trace length $N$ (leaves)")
    ax_b.set_ylabel("On-chain decision time (s)")
    ax_b.set_title("(b) Decision time vs. trace length", fontsize=10)
    ax_b.grid(True, which="both", linestyle=":", alpha=0.5)
    ax_b.set_ylim(bottom=0)
    ax_b.legend(loc="center right", fontsize=7, framealpha=0.9)

    fig.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"{BASENAME}.pdf"
    png_path = out_dir / f"{BASENAME}.png"
    fig.savefig(pdf_path)
    fig.savefig(png_path, dpi=200)
    plt.close(fig)
    return pdf_path




def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=None)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    csv_path = args.csv or _find_default_csv()
    rows = _read_rows(csv_path)
    print(f"reading: {csv_path} ({len(rows)} workloads)")
    pdf = plot(rows, args.out_dir)
    print(f"wrote: {pdf}")


if __name__ == "__main__":
    main()
