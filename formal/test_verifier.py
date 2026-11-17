#!/usr/bin/env python3
"""Check rejection of unfinished proofs, false proofs and changed mapped sources."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default=os.environ.get("LEAN", "lean"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    lean = shutil.which(args.lean)
    if lean is None:
        raise SystemExit("Select the pinned Lean executable using --lean or LEAN.")
    lean = str(Path(lean).absolute())
    manifest = json.loads((ROOT / "source-manifest.json").read_text())
    outcomes = []
    cases = [
        ("unfinished-proof", "Proof source gate"),
        ("custom-axiom", "Proof source gate"),
        ("false-proof", "tactic 'rfl' failed"),
        ("changed-mapped-source", "Source correspondence requires review"),
        ("five-member-group", "omega could not prove the goal"),
        ("rounding-boundary", "omega could not prove the goal"),
        ("reusable-failed-challenger", "omega could not prove the goal"),
    ]
    weakened_conditions = {
        "five-member-group": (
            "GroupedConversion.lean",
            "(hn : members ≤ 4)\n    (hd : degree",
            "(hn : members ≤ 5)\n    (hd : degree",
            "members=5, degree=15, carry=3 exceeds capacity 15",
        ),
        "rounding-boundary": (
            "Linear.lean",
            "(upper : 2 * noise < delta)",
            "(upper : 2 * noise ≤ delta)",
            "delta=2, m=0, noise=1 reaches the upper decoding boundary",
        ),
        "reusable-failed-challenger": (
            "Liveness.lean",
            "| falseChallenge (n) : Progress height (.pending n) (.audit n)",
            "| falseChallenge (n) : Progress height (.pending n) (.audit (n + 1))",
            "audit(n+1), bisection(n,height), pending(n), audit(n+1) forms a cycle",
        ),
    }
    with tempfile.TemporaryDirectory(prefix="vcfhe-proof-checker-") as temporary:
        for name, expected in cases:
            checkout = Path(temporary) / name
            formal = checkout / "formal"
            shutil.copytree(ROOT, formal,
                            ignore=shutil.ignore_patterns(".checked", ".lake", "__pycache__", "evidence"))
            for item in manifest["files"]:
                target = checkout / item["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT.parent / item["path"], target)
            proof = formal / "VCFHE/Quorum.lean"
            additions = {
                "unfinished-proof": "theorem unfinished_test : False := by sorry\n",
                "custom-axiom": "axiom extra_test_assumption : False\n",
                "false-proof": "theorem false_arithmetic_test : (0 : Nat) = 1 := by rfl\n",
            }
            if name in additions:
                proof.write_text(proof.read_text().replace("end VCFHE.Quorum",
                    additions[name] + "\nend VCFHE.Quorum"))
            elif name in weakened_conditions:
                filename, before, after, _ = weakened_conditions[name]
                proof = formal / "VCFHE" / filename
                text = proof.read_text()
                if text.count(before) != 1:
                    raise ValueError(f"Control requires one matching condition: {name}")
                proof.write_text(text.replace(before, after))
            else:
                target = checkout / manifest["files"][0]["path"]
                target.write_bytes(target.read_bytes() + b"\n// Source pin mutation test.\n")
            result = subprocess.run([sys.executable, str(formal / "check.py"), "--lean", lean],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    cwd=formal)
            passed = result.returncode != 0 and expected in result.stdout
            outcomes.append({"case": name, "expected": "rejected", "observed_exit": result.returncode,
                             "diagnostic_matched": expected if passed else None, "passed": passed})
            if name in weakened_conditions:
                outcomes[-1]["counterexample"] = weakened_conditions[name][3]
            print(f"{'PASS' if passed else 'ERROR'}: {name}", flush=True)
            if not passed:
                raise SystemExit(result.stdout)
    report = {"schema": "vcfhe-proof-checker-controls-v1", "status": "passed",
              "checked_cases": len(outcomes), "cases": outcomes}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
