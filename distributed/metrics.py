"""Summarize explicit distributed observations, retaining failures and missing data.

This is a supplementary collector/exporter. The current local campaign does not
emit distributed phase events. No synthetic or probe-only run is evaluation evidence.
"""
import csv
import json
import math
from pathlib import Path
import statistics

PHASES = {"owner_encryption", "owner_admission", "operator_computation", "auditor_recomputation",
          "context_certification", "disclosure", "bisection", "leaf_certification",
          "settlement", "finalization", "recipient_verification", "owner_approval", "authorized_release"}

def number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid nonnegative metric: "+name)
    return value

def percentile(values, p):
    values = sorted(values)
    if not values: return None
    index = (len(values)-1)*p
    lower = int(index)
    return values[lower]+(values[min(lower+1,len(values)-1)]-values[lower])*(index-lower)

def write_csv(path, rows, fields):
    with Path(path).open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def summarize(files, plan, output):
    output = Path(output)
    if output.exists(): raise ValueError("use a new supplementary result directory")
    hosts = {h["id"] for h in plan["hosts"]}
    roles = {n["id"]: n["host"] for n in plan["nodes"]}
    network, phases, transactions, releases, samples = [], [], [], [], []
    event_ids = set()
    for file in files:
        with Path(file).open() as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip(): continue
                row = json.loads(line)
                if row.get("host") not in hosts: raise ValueError("unknown source host")
                kind = row["kind"]
                if kind == "network_probe":
                    if row["target_host"] not in hosts or row["status"] not in ("connected", "unavailable"):
                        raise ValueError("invalid network observation")
                    number(row["elapsed_seconds"], "network time")
                    network.append({k: row.get(k) for k in ("host", "target_host", "port", "status", "elapsed_seconds", "utc")})
                elif kind == "host_sample":
                    samples.append(row)
                elif kind in ("phase", "transaction", "release"):
                    if row.get("role") not in roles or roles[row["role"]] != row["host"]:
                        raise ValueError("role event emitted on the wrong host")
                    identity = (row["host"], row["event_id"])
                    if identity in event_ids: raise ValueError("duplicate workflow event")
                    event_ids.add(identity)
                    if not row.get("case_id"): raise ValueError("missing case identity")
                    if kind == "phase":
                        if row["phase"] not in PHASES or row["status"] not in ("passed", "failed", "incomplete"):
                            raise ValueError("invalid workflow phase")
                        for field in ("elapsed_seconds", "cpu_seconds", "peak_rss_bytes", "payload_bytes_sent", "payload_bytes_received"):
                            number(row[field], field)
                        deadline = row.get("contract_deadline_timestamp")
                        receipt = row.get("receipt_block_timestamp")
                        if (deadline is None) != (receipt is None): raise ValueError("deadline requires a mined receipt timestamp")
                        if deadline is not None:
                            number(deadline, "deadline")
                            number(receipt, "receipt timestamp")
                        row["deadline_margin_seconds"] = None if deadline is None else deadline-receipt
                        phases.append(row)
                    elif kind == "transaction":
                        number(row["submission_to_receipt_seconds"], "transaction latency")
                        if row["status"] not in ("mined", "reverted", "timeout"): raise ValueError("invalid transaction status")
                        transactions.append(row)
                    else:
                        if row["status"] not in ("authorized_recovered", "rejected", "incomplete"):
                            raise ValueError("invalid release status")
                        # Do not export plaintext results or recipient/KMS secret material.
                        releases.append({k: row[k] for k in ("host", "role", "case_id", "event_id", "status")})
                else: raise ValueError(f"unknown event kind at {file}:{line_number}")
    output.mkdir(parents=True)
    write_csv(output/"network-connections.csv", network,
              ["host", "target_host", "port", "status", "elapsed_seconds", "utc"])
    fields = ["host", "role", "case_id", "phase", "status", "elapsed_seconds", "cpu_seconds",
              "peak_rss_bytes", "payload_bytes_sent", "payload_bytes_received", "deadline_margin_seconds"]
    write_csv(output/"workflow-phases.csv", [{k: r.get(k) for k in fields} for r in phases], fields)
    fields = ["host", "role", "case_id", "status", "submission_to_receipt_seconds"]
    write_csv(output/"transaction-latency.csv", [{k: r.get(k) for k in fields} for r in transactions], fields)
    write_csv(output/"authorized-releases.csv", releases, ["host", "role", "case_id", "event_id", "status"])
    grouped = []
    for phase in sorted({r["phase"] for r in phases}):
        group = [r for r in phases if r["phase"] == phase]
        success = [r["elapsed_seconds"] for r in group if r["status"] == "passed"]
        grouped.append({"phase": phase, "observations": len(group),
                        "passed": len(success), "failed_or_incomplete": len(group)-len(success),
                        "mean_success_seconds": statistics.mean(success) if success else None,
                        "median_success_seconds": statistics.median(success) if success else None,
                        "p95_success_seconds": percentile(success, .95),
                        "late_receipts": sum(r["deadline_margin_seconds"] is not None and r["deadline_margin_seconds"] < 0 for r in group)})
    write_csv(output/"phase-summary.csv", grouped, ["phase", "observations", "passed", "failed_or_incomplete",
               "mean_success_seconds", "median_success_seconds", "p95_success_seconds", "late_receipts"])
    result = {"schema": "vcfhe-distributed-supplement-v1", "evaluation_publishable": False,
              "publication_blocker": "Requires distributed protocol adapters, complete grid, raw seals and authorization validation",
              "network_observations": len(network), "resource_samples": len(samples),
              "phase_observations": len(phases), "release_observations": len(releases),
              "phase_summary": grouped,
              "network_metric": "TCP connection time. Not application message RTT or end-to-end latency.",
              "clock_rule": "Local monotonic duration. Contract deadlines use receipt block timestamps. No unsynchronized host timestamp subtraction."}
    (output/"summary.json").write_text(json.dumps(result, indent=2)+"\n")
    return result
