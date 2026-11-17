#!/usr/bin/env python3
"""Box plots of the linear workflow timings (timings_linear.csv).

Converts the per-step timing table of the implementation into four box-plot
panels, grouped by cost regime so each panel has one readable scale, with
each panel title naming the workflow step of the hybrid-overview figure,
panel (a):

  (a) step 1  record preparation (keygen, encrypt, commit, sign) and the
              two-pairing admission relation             -- linear in N
  (b) steps 2 and 3 (off-chain)  operator aggregation with output
              commitment, and the consumer's recomputation with balanced
              reduction and decryption                   -- constant in N
  (c) step 2  the on-chain result equality P(A) = P_agg  -- microseconds
  (d) avoided baseline at step 2: repeating the per-record pairing checks
              at result time                             -- linear in N

Each box shows the five seeded repeats of `output_binding_tfhe bench-timings`;
the individual repeats are overlaid as points (deterministic offsets, no
randomness). Colors reuse the palette of the repository's other figures.

Usage (from BN254-Signatures/):
  python3 scripts/plot_linear_timings.py                 # reads ./timings_linear.csv
  python3 scripts/plot_linear_timings.py --csv PATH --out-dir DIR --experiment-dir DIR

Only the Python standard library and matplotlib are required.
"""
from __future__ import annotations

import argparse
import csv
import shutil
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BLUE = "#2c7fb8"
ORANGE = "#d95f0e"
SIZES = [10, 50, 100, 200]

GROUPS = {
    "owner": ["owner_keygen", "encrypt", "commit_record", "sign_record"],
    "admission": ["admit_verify"],
    "operator": ["aggregate", "commit_output"],
    "result": ["result_check"],
    "consumer": ["consumer_recompute", "reduce_and_decrypt"],
    "baseline": ["agg_certificate_baseline"],
}


def load(csv_path: Path) -> dict[str, dict[int, list[float]]]:
    """group -> n -> per-repeat total elapsed_ms (phases of a group summed per repeat)."""
    raw: dict[str, dict[int, dict[int, float]]] = defaultdict(lambda: defaultdict(dict))
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            raw[row["phase"]][int(row["n"])][int(row["repeat"])] = float(row["elapsed_ms"])
    out: dict[str, dict[int, list[float]]] = {}
    for group, phases in GROUPS.items():
        out[group] = {}
        for n in SIZES:
            repeats = sorted(raw[phases[0]][n].keys())
            out[group][n] = [sum(raw[p][n][r] for p in phases) for r in repeats]
    return out


def boxes(ax, data_by_n, offset, color, label=None, scale=1.0):
    positions = [i + offset for i in range(len(SIZES))]
    values = [[v * scale for v in data_by_n[n]] for n in SIZES]
    bp = ax.boxplot(
        values,
        positions=positions,
        widths=0.26,
        patch_artist=True,
        medianprops={"color": color, "linewidth": 1.6},
        boxprops={"facecolor": color, "alpha": 0.18, "edgecolor": color, "linewidth": 1.1},
        whiskerprops={"color": color, "linewidth": 1.0},
        capprops={"color": color, "linewidth": 1.0},
        flierprops={"marker": ""},
    )
    # Overlay the five repeats with deterministic x offsets (no randomness).
    jitter = [-0.06, -0.03, 0.0, 0.03, 0.06]
    for i, vals in enumerate(values):
        xs = [positions[i] + jitter[k % len(jitter)] for k in range(len(vals))]
        ax.scatter(xs, vals, s=9, color=color, alpha=0.85, zorder=3, linewidths=0)
    if label is not None:
        bp["boxes"][0].set_label(label)
    return bp


def style(ax, ylabel):
    ax.set_xticks(range(len(SIZES)))
    ax.set_xticklabels([f"$N$={n}" for n in SIZES])
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", linewidth=0.4, alpha=0.35)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent.parent
    parser.add_argument("--csv", type=Path, default=here / "timings_linear.csv")
    parser.add_argument("--out-dir", type=Path, default=here / "plots")
    parser.add_argument("--experiment-dir", type=Path, default=None,
                        help="also copy the PDF here (e.g. the implementation folder)")
    args = parser.parse_args()

    data = load(args.csv)
    fig, axes = plt.subplots(2, 2, figsize=(9.2, 6.4))

    ax = axes[0][0]
    boxes(ax, data["owner"], -0.18, BLUE, "record preparation (owner)")
    boxes(ax, data["admission"], +0.18, ORANGE, "admission relation (two pairings/record)")
    style(ax, "time (ms)")
    ax.set_title("(a) Step 1: record preparation and admission", fontsize=10)
    ax.legend(fontsize=8, frameon=False, loc="upper left")

    ax = axes[0][1]
    boxes(ax, data["operator"], -0.18, BLUE, "operator: aggregation + output commitment")
    boxes(ax, data["consumer"], +0.18, ORANGE, "consumer: recompute + reduce + decrypt")
    style(ax, "time (ms)")
    ax.set_title("(b) Steps 2 and 3, off-chain: operator and consumer", fontsize=10)
    ax.set_ylim(0, 4.2)
    ax.legend(fontsize=8, frameon=False, loc="upper left")

    ax = axes[1][0]
    boxes(ax, data["result"], 0.0, BLUE, scale=1000.0)  # ms -> us
    style(ax, "time ($\\mu$s)")
    ax.set_title("(c) Step 2, on-chain acceptance: result equality $P(\\mathbf{A})=P_{agg}$", fontsize=10)
    ax.set_ylim(0, None)

    ax = axes[1][1]
    boxes(ax, data["baseline"], 0.0, ORANGE)
    style(ax, "time (ms)")
    ax.set_title("(d) Avoided at step 2: per-record pairings at result time", fontsize=10)

    fig.tight_layout()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = args.out_dir / "linear_timing_boxplots.pdf"
    png_path = args.out_dir / "linear_timing_boxplots.png"
    fig.savefig(pdf_path)
    fig.savefig(png_path, dpi=200)
    print(f"wrote {pdf_path}")
    print(f"wrote {png_path}")
    if args.experiment_dir is not None:
        args.experiment_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pdf_path, args.experiment_dir / pdf_path.name)
        print(f"copied {pdf_path.name} to {args.experiment_dir}")


if __name__ == "__main__":
    main()
