#!/usr/bin/env python3
"""Analysis and plots for the output-bound multi-key linear verification path.

Reads:
  - metrics_output_binding.csv
        off-chain multi-key metrics, from `cargo run --release -- bench`
  - the on-chain gas CSV, from `npm run onchain:tfhe-mk`
        (default ../BN254-Signatures/mklhs_tfhe_gas_results.csv, override with
         OB_ONCHAIN_CSV)

Writes PNGs into plots_output_binding/ and prints a summary table.
Only the standard library and matplotlib are required.
"""
import csv
import os
import statistics
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OFFCHAIN_CSV = os.environ.get(
    "OB_METRICS_CSV", os.path.join(HERE, "metrics_output_binding.csv")
)
# The linear path is curator-free, so the on-chain numbers come from the
# multi-key benchmark. Always give a default: an unset environment variable used
# to leave this None, which crashed the whole stage inside os.path.exists().
ONCHAIN_CSV = os.environ.get(
    "OB_ONCHAIN_CSV",
    os.path.join(HERE, "..", "BN254-Signatures", "mklhs_tfhe_gas_results.csv"),
)
OUTDIR = os.path.join(HERE, "plots_output_binding")

NEW_COLOR = "#3F5BF6"
OLD_COLOR = "#8C8C8C"
ACC_COLOR = "#F6883F"
DEP_COLOR = "#2CA02C"


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def mean_by(rows, key_col, val_col, filt=None):
    """Return sorted [(key, mean_value)] grouping rows by key_col."""
    buckets = {}
    for r in rows:
        if filt and not filt(r):
            continue
        k = float(r[key_col])
        buckets.setdefault(k, []).append(float(r[val_col]))
    return sorted((k, statistics.mean(v)) for k, v in buckets.items())


def dims_of(off):
    return sorted({float(r["cipher_dim_D"]) for r in off})


# ---------------------------------------------------------------- off-chain --


def plot_verification_is_constant(off):
    """Per-record admission and the result check do not grow with N."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    for d in dims_of(off):
        series = mean_by(
            off,
            "dataset_size",
            "admit_verify_per_record_ms",
            lambda r, d=d: float(r["cipher_dim_D"]) == d,
        )
        ax1.plot(
            [k for k, _ in series],
            [v for _, v in series],
            "o-",
            label=f"D={int(d)}",
        )
    ax1.set_title("Admission: one 2-pairing check per record")
    ax1.set_xlabel("dataset size N")
    ax1.set_ylabel("per-record verification (ms)")
    ax1.set_ylim(0, None)
    ax1.grid(True, alpha=0.3)
    ax1.legend()

    series = mean_by(off, "dataset_size", "result_check_ms")
    ax2.plot(
        [k for k, _ in series],
        [v * 1000.0 for _, v in series],
        "s-",
        color=NEW_COLOR,
        label="result check P(A') == P_agg",
    )
    ax2.set_title("Result verification is O(1) and pairing-free")
    ax2.set_xlabel("dataset size N")
    ax2.set_ylabel("result check (us)")
    ax2.set_ylim(0, None)
    ax2.grid(True, alpha=0.3)
    ax2.legend()

    fig.tight_layout()
    out = os.path.join(OUTDIR, "offchain_verify.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def per_input_us(off, col):
    """Mean per-input cost in microseconds, grouped by D, from a per-dataset column."""
    buckets = {}
    for r in off:
        d = float(r["cipher_dim_D"])
        buckets.setdefault(d, []).append(
            float(r[col]) / float(r["dataset_size"]) * 1000.0
        )
    return sorted((d, statistics.mean(v)) for d, v in buckets.items())


def plot_sign_vs_dim(off):
    """Cost of binding the output.

    The owner's per-input work is the commitment P(c_i), which is O(D) group
    operations, plus one MapToGroup and one scalar multiplication, which are
    constant in D. The input-hash baseline replaces the commitment by a Keccak
    digest, so its group work does not grow with D. The gap between the two
    curves is the cost of putting the ciphertext inside the signed statement.
    """
    commit_us = per_input_us(off, "commit_inputs_ms")
    sign_us = mean_by(off, "cipher_dim_D", "sign_per_input_us")
    total = [(d, c + s) for (d, c), (_, s) in zip(commit_us, sign_us)]
    legacy = per_input_us(off, "legacy_sign_ms")

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    ax.plot([k for k, _ in total], [v for _, v in total], "o-", color=NEW_COLOR,
            label="output-bound owner cost: P(c_i) + sigma_i")
    ax.plot([k for k, _ in commit_us], [v for _, v in commit_us], "^:", color=ACC_COLOR,
            label="commitment P(c_i) alone, O(D)")
    ax.plot([k for k, _ in sign_us], [v for _, v in sign_us], "d-.", color=DEP_COLOR,
            label="signature sigma_i alone, O(1) in D")
    ax.plot([k for k, _ in legacy], [v for _, v in legacy], "s--", color=OLD_COLOR,
            label="input-hash baseline")
    ax.set_title("Per-owner cost per input vs ciphertext dimension D")
    ax.set_xlabel("ciphertext dimension D")
    ax.set_ylabel("time per input (us)")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend(fontsize=8)
    fig.tight_layout()
    out = os.path.join(OUTDIR, "sign_cost_vs_dim.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def plot_aggregate_vs_admission(off):
    """Why the contract verifies per record instead of one aggregate certificate."""
    cert = mean_by(off, "dataset_size", "agg_certificate_ms")
    result = mean_by(off, "dataset_size", "result_check_ms")

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(
        [k for k, _ in cert],
        [v for _, v in cert],
        "o-",
        color=ACC_COLOR,
        label="off-chain aggregate certificate, (N+1) pairings",
    )
    ax.plot(
        [k for k, _ in result],
        [max(v, 1e-6) for _, v in result],
        "s-",
        color=NEW_COLOR,
        label="on-chain result check, O(1)",
    )
    ax.set_title("Aggregate certificate grows with N; the deployed check does not")
    ax.set_xlabel("dataset size N")
    ax.set_ylabel("verification time (ms)")
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3, which="both")
    ax.legend()
    fig.tight_layout()
    out = os.path.join(OUTDIR, "aggregate_vs_result_check.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ----------------------------------------------------------------- on-chain --


def plot_onchain_gas(onchain):
    def series(col, op):
        rows = [r for r in onchain if r["operation"] == op]
        return sorted((int(r["n"]), int(r[col])) for r in rows)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5))

    for op, marker, shade in (("SUM", "o-", 0), ("SUB", "s--", 1)):
        admit = series("admit_record_gas_mean", op)
        submit = series("submit_result_gas", op)
        reg = series("register_key_gas_mean", op)
        if not admit:
            continue
        ax1.plot([n for n, _ in admit], [g for _, g in admit], marker,
                 color=(NEW_COLOR, "#8FA3FB")[shade], label=f"admitRecord ({op})")
        ax1.plot([n for n, _ in reg], [g for _, g in reg], marker,
                 color=(ACC_COLOR, "#F8BC8F")[shade], label=f"registerOwnerKey ({op})")
        ax1.plot([n for n, _ in submit], [g for _, g in submit], marker,
                 color=(DEP_COLOR, "#8CD68C")[shade], label=f"submitResultBound ({op})")

    ax1.set_title("Per-owner and result gas, constant in N")
    ax1.set_xlabel("dataset size N")
    ax1.set_ylabel("gas")
    ax1.set_ylim(0, None)
    ax1.grid(True, alpha=0.3)
    ax1.legend(fontsize=7)

    for op, marker, shade in (("SUM", "o-", 0), ("SUB", "s--", 1)):
        dep = series("deployment_gas", op)
        if not dep:
            continue
        ax2.plot([n for n, _ in dep], [g for _, g in dep], marker,
                 color=(DEP_COLOR, "#8CD68C")[shade], label=f"deployment ({op})")
    ax2.set_title("Deployment gas, O(N) in enrolled owners")
    ax2.set_xlabel("dataset size N")
    ax2.set_ylabel("gas")
    ax2.grid(True, alpha=0.3)
    ax2.legend()

    fig.tight_layout()
    out = os.path.join(OUTDIR, "onchain_gas.png")
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


# ------------------------------------------------------------------ summary --


def print_summary(off, onchain):
    print("=" * 78)
    print("OUTPUT-BOUND MULTI-KEY LINEAR VERIFICATION -- METRICS SUMMARY")
    print("=" * 78)

    if onchain:
        print("\nOn-chain gas (MKLHS-Verification.sol, per-owner keys):")
        print(
            f"  {'N':>5} {'op':>4} {'deployment':>12} {'keyReg':>10} "
            f"{'admit':>10} {'submit':>10}  checks"
        )
        for r in sorted(onchain, key=lambda r: (int(r["n"]), r["operation"])):
            print(
                f"  {int(r['n']):>5} {r['operation']:>4} "
                f"{int(r['deployment_gas']):>12} "
                f"{int(r['register_key_gas_mean']):>10} "
                f"{int(r['admit_record_gas_mean']):>10} "
                f"{int(r['submit_result_gas']):>10}"
                f"  adversarial={r.get('adversarial_checks', 'n/a')}"
                f" digest={r.get('consumer_digest_match', 'n/a')}"
                f" commitment={r.get('consumer_commitment_match', 'n/a')}"
            )
        sub = [int(r["submit_result_gas"]) for r in onchain]
        print(
            f"\n  submitResultBound: min={min(sub)} max={max(sub)} "
            f"spread={max(sub) - min(sub)} "
            f"({100 * (max(sub) - min(sub)) / min(sub):.4f}% => O(1) in N)"
        )
        adm = [int(r["admit_record_gas_mean"]) for r in onchain]
        print(
            f"  admitRecord (mean per record): min={min(adm)} max={max(adm)} "
            f"spread={max(adm) - min(adm)} "
            f"({100 * (max(adm) - min(adm)) / min(adm):.2f}%, MapToGroup trial count)"
        )
    else:
        print(f"\n(on-chain CSV not found at {ONCHAIN_CSV}; run npm run onchain:tfhe-mk)")

    print("\nOff-chain per-owner cost per input, mean over N and repeats (us):")
    print(
        f"  {'D':>6} {'P(c_i)':>12} {'sigma_i':>12} {'total':>12} "
        f"{'input-hash':>12} {'admit/record (ms)':>19}"
    )
    for d in dims_of(off):
        sel = [r for r in off if float(r["cipher_dim_D"]) == d]
        com = statistics.mean(
            float(r["commit_inputs_ms"]) / float(r["dataset_size"]) * 1000.0 for r in sel
        )
        sign = statistics.mean(float(r["sign_per_input_us"]) for r in sel)
        legacy = statistics.mean(
            float(r["legacy_sign_ms"]) / float(r["dataset_size"]) * 1000.0 for r in sel
        )
        admit = statistics.mean(float(r["admit_verify_per_record_ms"]) for r in sel)
        print(
            f"  {int(d):>6} {com:>12.1f} {sign:>12.1f} {com + sign:>12.1f} "
            f"{legacy:>12.1f} {admit:>19.3f}"
        )

    res = [float(r["result_check_ms"]) for r in off]
    cert = mean_by(off, "dataset_size", "agg_certificate_ms")
    print(f"\n  result check (all D, all N): mean={statistics.mean(res) * 1000:.2f} us")
    print("  aggregate certificate, (N+1) pairings:")
    for n, v in cert:
        print(f"    N={int(n):>5}: {v:.1f} ms")

    print("\nSizes (compressed encodings):")
    r0 = off[0]
    print(f"  per-owner signature  = {r0['single_sig_bytes']} bytes (G1)")
    print(f"  aggregate signature  = {r0['agg_sig_bytes']} bytes (G1)")
    print(f"  output commitment    = {r0['output_commitment_bytes']} bytes (G1)")
    print(f"  owner public key     = {r0['pubkey_bytes']} bytes (G2)")
    print("=" * 78)


def main():
    if not os.path.exists(OFFCHAIN_CSV):
        print(
            f"Missing {OFFCHAIN_CSV}. Run: cargo run --release -- bench",
            file=sys.stderr,
        )
        sys.exit(1)
    os.makedirs(OUTDIR, exist_ok=True)
    off = read_csv(OFFCHAIN_CSV)

    expected = {
        "cipher_dim_D",
        "dataset_size",
        "sign_per_input_us",
        "commit_inputs_ms",
        "legacy_sign_ms",
        "admit_verify_per_record_ms",
        "result_check_ms",
        "agg_certificate_ms",
    }
    missing = expected - set(off[0].keys())
    if missing:
        print(
            f"{OFFCHAIN_CSV} is missing columns {sorted(missing)}; it was produced "
            "by an older build. Regenerate it with `cargo run --release -- bench`.",
            file=sys.stderr,
        )
        sys.exit(1)

    written = [
        plot_verification_is_constant(off),
        plot_sign_vs_dim(off),
        plot_aggregate_vs_admission(off),
    ]

    onchain = read_csv(ONCHAIN_CSV) if os.path.exists(ONCHAIN_CSV) else []
    if onchain:
        written.append(plot_onchain_gas(onchain))
    print_summary(off, onchain)

    print("\nPlots written:")
    for w in written:
        print("  " + w)


if __name__ == "__main__":
    main()
