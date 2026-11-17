#!/usr/bin/env python3
"""Post-run consistency check for the linear-path artifacts.

The linear pipeline writes six artifacts from four different processes. Each one
is self-validating, but nothing checked that they AGREE with each other, or that
they agree with the constants the implementation states. A run can therefore finish
"green" while, for example, the gas table covers sizes the security matrix never
saw, or the MapToGroup fit is quoted from a stale text file.

This script is read-only. It is the last step of `run-linear.sh`, and it exits
non-zero when any invariant below fails.

CHECKS
------
 1. Every expected artifact exists and is non-empty.
 2. The gas table has both SUM and SUB for every requested N.
 3. Result-submission gas is constant in N (the implementation's O(1) claim).
 4. Key-registration gas is constant in N (per-owner, independent of N).
 5. Deployment gas grows monotonically with N (enrolment storage is O(N)).
 6. The adversarial audit reverted every attack.
 7. The security matrix passed every scenario AND ran on the consensus chain.
 8. The MapToGroup JSON and the legacy text file report the same coefficients,
    so a stale .txt can never be transcribed into the implementation.
 9. The leveled-regime bounds implied by the parameters match the implementation
    (N <= 102 from the message budget, N <= 33 from the 12-sigma noise budget).

USAGE
-----
    python3 scripts/check_linear_artifacts.py
    python3 scripts/check_linear_artifacts.py --sizes 10,50,100,200
    python3 scripts/check_linear_artifacts.py --require-qbft   # fail off-chain runs
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # .../BN254-Signatures
VCFHE = ROOT.parent

# Leveled LWE parameters, mirrored from src/bin/output_binding_tfhe.rs.
MSG_BITS = 10
DELTA = 1 << (64 - MSG_BITS)
LWE_STD_DEV = 0.000_007_069_849_454_709_433
RATING_MAX = 5

failures: list[str] = []
notes: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"  {mark}  {label}{('  ' + detail) if detail else ''}")
    if not ok:
        failures.append(f"{label}{(': ' + detail) if detail else ''}")
    return ok


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", default="", help="comma-separated N values the run requested")
    parser.add_argument("--require-qbft", action="store_true",
                        help="fail if any on-chain artifact was produced off the QBFT network")
    args = parser.parse_args()
    requested = [int(x) for x in args.sizes.split(",") if x.strip()] if args.sizes else []

    print("Linear-path artifact consistency check")
    print("=" * 60)

    # -- 1. presence ------------------------------------------------------
    expected = {
        "gas table": ROOT / "mklhs_tfhe_gas_results.csv",
        "attacker-cost audit": ROOT / "mklhs_adversarial_results.csv",
        "security matrix": ROOT / "mklhs_security_evaluation.csv",
        "MapToGroup fit (json)": ROOT / "mklhs_maptogroup_fit.json",
        "MapToGroup admissions": ROOT / "mklhs_maptogroup_admissions.csv",
        "off-chain metrics": VCFHE / "output-binding-lhs" / "metrics_output_binding.csv",
    }
    for label, path in expected.items():
        exists = path.exists() and path.stat().st_size > 0
        check(exists, f"artifact present: {label}", "" if exists else str(path))
    if failures:
        print("\nMissing artifacts; run ./run-linear.sh first.")
        return 1

    # -- 2/3/4/5. gas table -----------------------------------------------
    gas = read_csv(expected["gas table"])
    sizes = sorted({int(r["n"]) for r in gas})
    ops = {r["operation"] for r in gas}
    check(ops == {"SUM", "SUB"}, "gas table covers both authorized operations", f"ops={sorted(ops)}")
    if requested:
        check(sizes == sorted(requested), "gas table covers every requested N",
              f"requested={sorted(requested)} present={sizes}")

    submits = {int(r["submit_result_gas"]) for r in gas}
    spread = max(submits) - min(submits)
    # The result check is a G1 equality plus fixed-size storage: any variation is
    # calldata byte pricing on run-specific hashes, not a dependence on N.
    check(spread <= 200, "result submission is O(1) in N",
          f"spread={spread} gas over N={sizes}")

    regs = {int(r["register_key_gas_mean"]) for r in gas}
    check(max(regs) - min(regs) <= 200, "key registration is independent of N",
          f"spread={max(regs) - min(regs)} gas")

    deploy_by_n = {}
    for r in gas:
        if r["operation"] == "SUM":
            deploy_by_n[int(r["n"])] = int(r["deployment_gas"])
    ordered = [deploy_by_n[n] for n in sorted(deploy_by_n)]
    check(all(a < b for a, b in zip(ordered, ordered[1:])),
          "deployment gas grows with N (enrolment storage is O(N))",
          f"{ordered}")

    consumer_ok = all(r["consumer_digest_match"] == "true" and
                      r["consumer_commitment_match"] == "true" for r in gas)
    check(consumer_ok, "consumer digest and commitment matched on every row")

    adv_ok = all(r["adversarial_checks"].split("/")[0] == r["adversarial_checks"].split("/")[1]
                 for r in gas)
    check(adv_ok, "per-row adversarial checks all passed",
          f"{sorted({r['adversarial_checks'] for r in gas})}")

    # -- 6. attacker-cost audit -------------------------------------------
    audit = read_csv(expected["attacker-cost audit"])
    reverted = [r for r in audit if r["reverted"] == "true"]
    check(len(reverted) == len(audit), "every attack in the attacker-cost audit reverted",
          f"{len(reverted)}/{len(audit)}")

    # -- 7. security matrix ------------------------------------------------
    sec = read_csv(expected["security matrix"])
    passed = [r for r in sec if r["status"] == "PASS"]
    check(len(passed) == len(sec), "every security scenario matched the implementation",
          f"{len(passed)}/{len(sec)}")
    venues = {r["venue"] for r in sec}
    on_chain = venues == {"qbft-network"}
    if args.require_qbft:
        check(on_chain, "security matrix ran on the QBFT network", f"venue={sorted(venues)}")
    elif not on_chain:
        notes.append(f"security matrix venue is {sorted(venues)}, not the QBFT network")
    classes = {r["expectedOutcome"] for r in sec}
    check("accepted-limitation" in classes,
          "security matrix exercises the conceded limitations, not only the rejections",
          f"classes={sorted(classes)}")

    # -- 8. MapToGroup fit: json vs legacy text ---------------------------
    fit = json.loads((ROOT / "mklhs_maptogroup_fit.json").read_text())
    txt_path = ROOT / "mklhs_maptogroup_fit.txt"
    if txt_path.exists():
        txt = txt_path.read_text()
        m = re.search(r"marginal gas per trial = (\d+), base = (\d+)", txt)
        if m:
            same = (int(m.group(1)) == fit["marginalGasPerTrial"] and
                    int(m.group(2)) == fit["baseGas"])
            check(same, "MapToGroup text and JSON agree",
                  f"txt=({m.group(1)}, {m.group(2)}) json=({fit['marginalGasPerTrial']}, {fit['baseGas']})")
        else:
            notes.append("MapToGroup text file has an unrecognised format; JSON is authoritative")
    admissions = read_csv(expected["MapToGroup admissions"])
    fitted = [r for r in admissions if r["in_fit"] == "true"]
    check(len(fitted) == fit["fittedAdmissions"],
          "MapToGroup admissions CSV matches the fit population",
          f"csv={len(fitted)} json={fit['fittedAdmissions']}")
    check(fit["maxTrials"] <= 256, "MapToGroup trial count within the contract bound",
          f"max={fit['maxTrials']} bound=256")

    # -- 9. leveled-regime bounds vs the implementation -----------------------
    sigma_e = LWE_STD_DEV * (2.0 ** 64)
    n_msg = (1 << (MSG_BITS - 1)) // RATING_MAX          # |sum w_i m_i| < 2^(l-1)
    n_noise = math.floor(((DELTA / 2) / (12.0 * sigma_e)) ** 2)   # 12-sigma budget
    check(n_msg == 102, "message budget matches the implementation (N <= 102)", f"computed={n_msg}")
    check(n_noise == 33, "12-sigma noise budget matches the implementation (N <= 33)",
          f"computed={n_noise}")
    beyond = [n for n in sizes if n > n_noise]
    if beyond:
        notes.append(
            f"gas rows exist for N={beyond}, beyond the exact-decryption budget N<={n_noise}; "
            "the implementation already states these are gas measurements only"
        )

    # -- report ------------------------------------------------------------
    print("=" * 60)
    for note in notes:
        print(f"  note: {note}")
    if failures:
        print(f"\n{len(failures)} consistency check(s) FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nAll linear artifacts are mutually consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
