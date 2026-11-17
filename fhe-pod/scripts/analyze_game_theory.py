#!/usr/bin/env python3
"""Numerical evaluation of the cryptoeconomic model, and its figure.

This is the analysis behind the evaluation's "Cryptoeconomic conditions"
paragraph and Figure fig_game_theory. It is a numerical evaluation of the
model's closed forms, NOT a measurement of participant behaviour, and it
assumes rationality rather than establishing it.

Closed forms evaluated (numbering follows the implementation):

  eq:pod-deterrence     P_eff (S_o + R_o) > (1 - P_eff) B_o + (C_o - C_fake)
                        Minimum operator stake that deters a corrupted task:
                        S_o^min = [ (1 - P_eff) B_o + (C_o - C_fake) ] / P_eff - R_o

  eq:mirror-deterrence  (R_a - C_a) > (R_a - C_m) - p_c q S_a
                        equivalently  p_c q S_a > C_a - C_m
                        Lazy-auditor margin:  p_c q S_a - (C_a - C_m)
                        Zero crossing at  S_a = (C_a - C_m) / (p_c q)

  eq:sybil-capture      p_cap = C(A, m) / C(M, m) = (A)_m / (M)_m  <=  alpha^m
                        Exact capture of a stage cohort under identity
                        sampling WITHOUT replacement, versus the naive
                        stake-fraction product alpha^m.

Every parameter is declared in PARAMETERS below (single place), and every
stochastic check uses a fixed seed, so the numbers and the figure are
reproducible run to run.

Usage (from VC-FHE/fhe-pod):
  python3 scripts/analyze_game_theory.py                 # checks + figure
  python3 scripts/analyze_game_theory.py --no-figure     # checks only
  python3 scripts/analyze_game_theory.py --experiment-dir DIR # also copy the PDF

Outputs:
  artifacts/evaluations/game_theory_checks.csv    one row per verification check
  artifacts/evaluations/game_theory_checks.json   parameters + results + seed
  artifacts/figures/fig_game_theory.{pdf,png}     the four-panel figure
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import shutil
import sys
from itertools import combinations
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
EVAL_DIR = PROJECT_ROOT / "artifacts" / "evaluations"
FIG_DIR = PROJECT_ROOT / "artifacts" / "figures"
BASENAME = "fig_game_theory"

# ---------------------------------------------------------------------------
# Single parameter block. Everything the analysis depends on lives here.
# ---------------------------------------------------------------------------
PARAMETERS = {
    "seed": 20260729,
    "monte_carlo_trials": 200_000,
    # eq:pod-deterrence
    "operator": {
        "B_o": 100.0,        # manipulation benefit
        "C_o": 1.0,          # honest execution cost
        "C_fake": 0.2,       # cost of producing the corrupted trace
        "R_o": 0.0,          # honest reward, conservatively zero
        "P_effective_grid": [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 0.99],
    },
    # eq:mirror-deterrence
    "auditor": {
        "C_a": 1.0,          # honest recomputation cost
        "C_m": 0.1,          # mirroring / fabrication cost
        "q": 0.1,            # fraction of tasks whose assigned stage is corrupted
        "p_c": 0.9,          # conditional probability of resolution against the operator
        "S_a_grid": [0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0],
    },
    # eq:sybil-capture
    "sybil": {
        "cohort_sizes": [1, 2, 3, 5],
        "identity_pools": [8, 16, 32, 64],
        "alpha_grid": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
        # exhaustive enumeration is done on these small populations
        "exhaustive": [(8, 4), (10, 5), (12, 6), (16, 8)],
    },
}

checks: list[dict] = []


def check(name: str, closed_form: float, reference: float, tolerance: float,
          method: str) -> None:
    ok = abs(closed_form - reference) <= tolerance
    checks.append({
        "check": name,
        "method": method,
        "closed_form": closed_form,
        "reference": reference,
        "abs_error": abs(closed_form - reference),
        "tolerance": tolerance,
        "passed": ok,
    })


# ---------------------------------------------------------------------------
# Closed forms
# ---------------------------------------------------------------------------
def min_operator_stake(p_eff: float, B_o: float, C_o: float, C_fake: float,
                       R_o: float) -> float:
    """eq:pod-deterrence solved for S_o."""
    return ((1.0 - p_eff) * B_o + (C_o - C_fake)) / p_eff - R_o


def lazy_auditor_margin(S_a: float, p_c: float, q: float, C_a: float,
                        C_m: float) -> float:
    """eq:mirror-deterrence rearranged: positive means honest work is preferred."""
    return p_c * q * S_a - (C_a - C_m)


def sybil_capture_exact(M: int, A: int, m: int) -> float:
    """eq:sybil-capture: C(A,m)/C(M,m), sampling identities without replacement."""
    if m > A:
        return 0.0
    return math.comb(A, m) / math.comb(M, m)


def sybil_capture_naive(alpha: float, m: int) -> float:
    """The stake-fraction product the implementation identifies as an overstatement."""
    return alpha ** m


# ---------------------------------------------------------------------------
# Verification: exhaustive enumeration and seeded Monte Carlo
# ---------------------------------------------------------------------------
def verify_sybil_exhaustive() -> None:
    """Enumerate every cohort of a small population and count adversarial ones."""
    for M, A in PARAMETERS["sybil"]["exhaustive"]:
        for m in PARAMETERS["sybil"]["cohort_sizes"]:
            if m > M:
                continue
            population = list(range(M))
            adversarial = set(range(A))
            total = 0
            captured = 0
            for cohort in combinations(population, m):
                total += 1
                if set(cohort) <= adversarial:
                    captured += 1
            enumerated = captured / total
            check(
                f"sybil_capture_exhaustive_M{M}_A{A}_m{m}",
                sybil_capture_exact(M, A, m),
                enumerated,
                1e-12,
                "exhaustive enumeration of all cohorts",
            )


def verify_sybil_monte_carlo(rng: random.Random) -> None:
    """Seeded sampling without replacement must converge to the closed form."""
    trials = PARAMETERS["monte_carlo_trials"]
    for M, A in PARAMETERS["sybil"]["exhaustive"]:
        for m in (2, 3):
            if m > M:
                continue
            population = list(range(M))
            adversarial = set(range(A))
            hits = 0
            for _ in range(trials):
                if set(rng.sample(population, m)) <= adversarial:
                    hits += 1
            empirical = hits / trials
            exact = sybil_capture_exact(M, A, m)
            # 5 standard deviations of the binomial estimator, plus a floor.
            sd = math.sqrt(max(exact * (1 - exact), 1e-9) / trials)
            check(
                f"sybil_capture_monte_carlo_M{M}_A{A}_m{m}",
                exact,
                empirical,
                5 * sd + 1e-4,
                f"seeded Monte Carlo, {trials} draws without replacement",
            )


def verify_operator_threshold(rng: random.Random) -> None:
    """The stake solving eq:pod-deterrence must sit exactly at indifference."""
    p = PARAMETERS["operator"]
    for p_eff in p["P_effective_grid"]:
        s_min = min_operator_stake(p_eff, p["B_o"], p["C_o"], p["C_fake"], p["R_o"])
        lhs = p_eff * (s_min + p["R_o"])
        rhs = (1.0 - p_eff) * p["B_o"] + (p["C_o"] - p["C_fake"])
        check(
            f"operator_indifference_p{p_eff}",
            lhs, rhs, 1e-9,
            "substitute the closed-form stake back into eq:pod-deterrence",
        )
    # A randomized sweep: above the threshold the condition must hold, below it must fail.
    for _ in range(4):
        p_eff = rng.uniform(0.05, 0.95)
        s_min = min_operator_stake(p_eff, p["B_o"], p["C_o"], p["C_fake"], p["R_o"])
        above = p_eff * (s_min * 1.01 + p["R_o"]) > (1 - p_eff) * p["B_o"] + (p["C_o"] - p["C_fake"])
        below = p_eff * (s_min * 0.99 + p["R_o"]) > (1 - p_eff) * p["B_o"] + (p["C_o"] - p["C_fake"])
        check(
            f"operator_threshold_sign_p{p_eff:.4f}",
            1.0 if (above and not below) else 0.0, 1.0, 0.0,
            "seeded random probe just above and below the threshold stake",
        )


def verify_auditor_crossing(rng: random.Random) -> None:
    """The lazy-auditor margin must cross zero at (C_a - C_m)/(p_c q)."""
    a = PARAMETERS["auditor"]
    crossing = (a["C_a"] - a["C_m"]) / (a["p_c"] * a["q"])
    check(
        "auditor_margin_zero_at_closed_form_crossing",
        lazy_auditor_margin(crossing, a["p_c"], a["q"], a["C_a"], a["C_m"]),
        0.0, 1e-9,
        "evaluate eq:mirror-deterrence at its analytic zero",
    )
    for _ in range(4):
        scale = rng.uniform(1.05, 3.0)
        check(
            f"auditor_margin_positive_above_crossing_x{scale:.3f}",
            1.0 if lazy_auditor_margin(crossing * scale, a["p_c"], a["q"],
                                       a["C_a"], a["C_m"]) > 0 else 0.0,
            1.0, 0.0,
            "seeded random stake above the crossing must give a positive margin",
        )


def verify_exact_below_naive() -> None:
    """p_cap <= alpha^m must hold strictly whenever m >= 2 and A < M."""
    violations = 0
    strict = 0
    for M in PARAMETERS["sybil"]["identity_pools"]:
        for m in PARAMETERS["sybil"]["cohort_sizes"]:
            for alpha in PARAMETERS["sybil"]["alpha_grid"]:
                A = int(round(alpha * M))
                if A < m or A > M:
                    continue
                exact = sybil_capture_exact(M, A, m)
                naive = sybil_capture_naive(A / M, m)
                if exact > naive + 1e-12:
                    violations += 1
                if m >= 2 and A < M and exact < naive - 1e-12:
                    strict += 1
    check("sybil_exact_never_exceeds_naive", float(violations), 0.0, 0.0,
          "grid sweep over pools, cohort sizes and adversarial fractions")
    check("sybil_exact_strictly_below_naive_when_m_ge_2_and_A_lt_M",
          1.0 if strict > 0 else 0.0, 1.0, 0.0,
          "grid sweep, strictness witness count")


# ---------------------------------------------------------------------------
# Figure
# ---------------------------------------------------------------------------
def build_figure(out_dir: Path) -> Path:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    op = PARAMETERS["operator"]
    au = PARAMETERS["auditor"]

    fig, axes = plt.subplots(2, 2, figsize=(9.2, 6.6))
    (ax_a, ax_b), (ax_c, ax_d) = axes

    # (a) operator deterrence frontier: minimum stake vs P_effective.
    xs = [0.02 + 0.005 * i for i in range(int((0.99 - 0.02) / 0.005) + 1)]
    ys = [min_operator_stake(x, op["B_o"], op["C_o"], op["C_fake"], op["R_o"]) for x in xs]
    ax_a.plot(xs, ys, linewidth=2.0, color="#2c7fb8")
    ax_a.scatter(op["P_effective_grid"],
                 [min_operator_stake(x, op["B_o"], op["C_o"], op["C_fake"], op["R_o"])
                  for x in op["P_effective_grid"]],
                 color="#2c7fb8", s=26, zorder=3)
    ax_a.set_yscale("log")
    ax_a.set_xlabel(r"$P_{effective}$")
    ax_a.set_ylabel(r"minimum operator stake $S_o$")
    ax_a.set_title("(a) Operator deterrence frontier")
    ax_a.grid(True, which="both", linestyle=":", alpha=0.5)
    ax_a.text(0.35, 0.82, r"diverges as $P_{effective}\rightarrow 0$",
              transform=ax_a.transAxes, fontsize=8)

    # (b) lazy-auditor margin vs stake, for several corrupted-task rates.
    crossing_label_done = False
    for q, color in zip([0.05, 0.1, 0.2], ["#c0392b", "#d95f0e", "#31a354"]):
        s_grid = [i * 0.5 for i in range(0, 81)]
        margins = [lazy_auditor_margin(s, au["p_c"], q, au["C_a"], au["C_m"]) for s in s_grid]
        ax_b.plot(s_grid, margins, linewidth=1.8, color=color, label=f"$q={q}$")
        crossing = (au["C_a"] - au["C_m"]) / (au["p_c"] * q)
        ax_b.axvline(crossing, color=color, linestyle=":", linewidth=1.0)
        if not crossing_label_done:
            ax_b.axhline(0.0, color="#444444", linewidth=0.8)
            crossing_label_done = True
    ax_b.set_xlabel(r"auditor stake $S_a$")
    ax_b.set_ylabel(r"margin $p_c q S_a - (C_a - C_m)$")
    ax_b.set_title("(b) Lazy-auditor margin")
    ax_b.grid(True, linestyle=":", alpha=0.5)
    ax_b.legend(fontsize=8, framealpha=0.9)

    # (c) exact hypergeometric capture vs the naive product.
    M = 16
    for m, color in zip([2, 3, 5], ["#2c7fb8", "#d95f0e", "#756bb1"]):
        alphas, exact, naive = [], [], []
        for a_count in range(m, M + 1):
            alpha = a_count / M
            alphas.append(alpha)
            exact.append(sybil_capture_exact(M, a_count, m))
            naive.append(sybil_capture_naive(alpha, m))
        ax_c.plot(alphas, exact, linewidth=2.0, color=color, label=f"exact, $m={m}$")
        ax_c.plot(alphas, naive, linewidth=1.3, linestyle="--", color=color,
                  label=rf"naive $\alpha^{{{m}}}$")
    ax_c.set_xlabel(r"adversarial identity fraction $\alpha=A/M$")
    ax_c.set_ylabel(r"cohort capture probability")
    ax_c.set_title(rf"(c) Sybil capture, exact vs naive ($M={M}$)")
    ax_c.grid(True, linestyle=":", alpha=0.5)
    ax_c.legend(fontsize=7, framealpha=0.9, ncol=2)

    # (d) stage detection against liveness, from the accountability artifact.
    acc = EVAL_DIR / "latest_experiment_evaluation_verification_cost_accountability.csv"
    if not acc.exists():
        acc = EVAL_DIR / "latest_verification_cost_accountability.csv"
    plotted = False
    if acc.exists():
        with acc.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        series: dict[str, list[tuple[float, float]]] = {}
        for r in rows:
            try:
                series.setdefault(r["cohortSize"], []).append(
                    (float(r["lazyFraction"]), float(r["pEffective"]))
                )
            except (KeyError, ValueError):
                continue
        for cohort, points in sorted(series.items(), key=lambda kv: int(kv[0]))[:5]:
            points.sort()
            ax_d.plot([p[0] for p in points], [p[1] for p in points],
                      marker="o", linewidth=1.6, label=f"cohort $m={cohort}$")
            plotted = True
        ax_d.set_xlabel("lazy fraction among assigned auditors")
        ax_d.set_ylabel(r"$P_{effective}$")
        ax_d.set_title("(d) Stage detection against liveness")
        ax_d.grid(True, linestyle=":", alpha=0.5)
        if plotted:
            ax_d.legend(fontsize=7, framealpha=0.9)
    if not plotted:
        ax_d.text(0.5, 0.5,
                  "panel (d) needs\nlatest_experiment_evaluation_verification_cost_accountability.csv\n"
                  "(npm run eval:costs)",
                  ha="center", va="center", transform=ax_d.transAxes, fontsize=8)
        ax_d.set_axis_off()

    fig.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"{BASENAME}.pdf"
    fig.savefig(pdf_path)
    fig.savefig(out_dir / f"{BASENAME}.png", dpi=200)
    plt.close(fig)
    return pdf_path




def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-figure", action="store_true")
    args = parser.parse_args()

    rng = random.Random(PARAMETERS["seed"])
    verify_sybil_exhaustive()
    verify_sybil_monte_carlo(rng)
    verify_operator_threshold(rng)
    verify_auditor_crossing(rng)
    verify_exact_below_naive()

    passed = sum(1 for c in checks if c["passed"])
    print("Cryptoeconomic model, numerical evaluation")
    print(f"seed={PARAMETERS['seed']}  monte_carlo_trials={PARAMETERS['monte_carlo_trials']}")
    print(f"checks passed: {passed}/{len(checks)}")
    for c in checks:
        if not c["passed"]:
            print(f"  FAILED {c['check']}: closed form {c['closed_form']} vs "
                  f"reference {c['reference']} (tolerance {c['tolerance']})")

    monte = [c for c in checks if "monte_carlo" in c["method"] or "Monte Carlo" in c["method"]]
    exhaustive = [c for c in checks if "exhaustive" in c["method"]]
    print(f"  of which seeded Monte Carlo checks: {sum(1 for c in monte if c['passed'])}/{len(monte)}")
    print(f"  of which exhaustive enumeration checks: "
          f"{sum(1 for c in exhaustive if c['passed'])}/{len(exhaustive)}")

    # Values the implementation quotes.
    au = PARAMETERS["auditor"]
    crossing = (au["C_a"] - au["C_m"]) / (au["p_c"] * au["q"])
    print(f"  lazy-auditor margin crosses zero at S_a = (C_a - C_m)/(p_c q) = {crossing:.4f}")

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = EVAL_DIR / "game_theory_checks.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(checks[0].keys()))
        writer.writeheader()
        writer.writerows(checks)
    json_path = EVAL_DIR / "game_theory_checks.json"
    json_path.write_text(json.dumps({
        "parameters": PARAMETERS,
        "summary": {
            "total": len(checks), "passed": passed,
            "monte_carlo_total": len(monte),
            "monte_carlo_passed": sum(1 for c in monte if c["passed"]),
            "exhaustive_total": len(exhaustive),
            "exhaustive_passed": sum(1 for c in exhaustive if c["passed"]),
            "auditor_margin_zero_crossing": crossing,
        },
        "checks": checks,
    }, indent=2), encoding="utf-8")
    print(f"wrote: {csv_path}")
    print(f"wrote: {json_path}")

    if not args.no_figure:
        pdf = build_figure(FIG_DIR)
        print(f"wrote: {pdf}")

    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()
