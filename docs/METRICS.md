# Measurement definitions

The current campaign keeps separate paired measurements, warm-ups and complete
workflows. Linear pairs have 100 repetitions per size. Nonlinear pairs have 30
repetitions per workload/size. Local full workflows have five cases per
configuration; distributed full workflows have three. Do not substitute paired
sample counts for the full-workflow count.

| Quantity | Interpretation |
| --- | --- |
| Elapsed time | Time between the recorded boundaries for one stage or workflow |
| Process CPU | CPU consumed by the named processes, potentially overlapping in wall time |
| Receipt time | Submission/receipt or mined-block interval, as named by the metric |
| Gas | Transaction execution units, independent of a selected currency price |
| RPC bytes | Serialized application messages, including base64 where present |
| Host NIC bytes | Host traffic with a broader scope than role RPC messages |
| Peak RSS | Peak memory for the named process; peaks cannot be summed as simultaneous usage |

The workflow tables identify shared, proposed, baseline and dispute stages.
An aggregate timer is not split when its internal stages were not instrumented.
Missing measurements remain missing, not zero. KMS/release diagnostics are kept
with a raw run and are not mixed into FHE verification cost comparisons.

## Final decision

The decision-timing analysis separates opening the challenge, bisection, terminal
adjudication and settlement from later bond/reward operations. Read each plot's
start and end boundaries. Full workflow duration, time to a final task decision
and later financial bookkeeping are different intervals. Contract deadline
margins use mined block timestamps to avoid subtracting unsynchronized host clocks.

## Communication and geographic deployment

Application request/response delays include TLS, transfer and remote handler work.
TCP connection probes are not application response times. Neither isolates the
causal contribution of geographic distance. There is no matched single-region
control in these observations. Three full cases per configuration do not estimate
extreme latency tails or production failure rates. Startup connection attempts
are not protocol failure observations.

## Result generators

| Module | Inputs and outputs |
| --- | --- |
| `campaign/export.py`, `campaign/poc_evidence.py` | Validated run records → CSV/JSON |
| `postprocess/single_run.py` | Native validation and seal → provenance and composite inputs |
| `postprocess/diagnostics.py`, `review.py` | Paired observations → diagnostics and bound review |
| `postprocess/workflow.py` | Raw cases/receipts → workflow observations, summaries and hashes |
| `postprocess/render.py` | Verified workflow → `metrics.csv`, `METRICS.md`, plot files |
| `postprocess/workflow_figures.py` | Linear costs, nonlinear CPU and workflow gas plots |
| `postprocess/decision_timing.py` | Receipt partition → decision and post-decision timing |
| `postprocess/verification_budget.py` | Retained per-process records → non-overlapping CPU budgets |
| `distributed/supplement.py`, `delay_metrics.py` | Distributed telemetry → communication and delay summaries |
| `results/reproduce.py` | Public numerical collection → verified summaries and optional plots |

The postprocess paths above are inside `threshold-kms/`. Each generated figure
has CSV/JSON values for inspection. Matplotlib writes PDF, PNG and SVG directly.
Component plotting tools under `BN254-Signatures/` and `fhe-pod/` describe their
own older or synthetic inputs. Their outputs are not interchangeable with the
current threshold campaign. Preserve source profiles when comparing results.
