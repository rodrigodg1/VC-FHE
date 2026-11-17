# Retained numerical results

This collection preserves observations from local and geographically distributed
PoC executions. It supports independent statistical verification and plot generation
without Docker or Google Cloud. It does not contain the raw keys, ciphertexts,
executables or chain databases required for complete protocol revalidation.

| Collection | Observation rows | Grouped metrics | Measured pairs | Warm-ups | Full cases |
| --- | ---: | ---: | ---: | ---: | ---: |
| `local-archive/` | 11,266 | 1,504 | 480 | 18 | 45 |
| `distributed/` | 8,392 | 1,504 | 480 | 18 | 27 |

The [Google Cloud results index](distributed/README.md) links the three main
plots, five retained supplementary plots and nine paired-diagnostic plots. It
also explains their measurement boundaries and the data included in this copy.

Each `collection.json` records SHA-256 hashes. CSV files retain their original
bytes. The summary and setup descriptors retain measurement fields with portable
provenance labels. These are new
numerical collection manifests, not replacement raw execution seals.

Read the [data dictionary](DATA-DICTIONARY.md) before joining tables or converting
integer fee fields. The [experiment guide](../docs/EXPERIMENTS.md) explains input
selection, baselines, sample counts and measured-versus-template configuration.

## Check the numbers

```bash
python3 results/reproduce.py
python3 results/reproduce.py --collection distributed
```

The script verifies file hashes, the metric inventory, observation counts, means,
sample standard deviations, and ranges. It preserves integer precision for gas/economic
quantities. It also reconciles the distributed receipt endpoints and per-process
CPU budgets, including context certification and full auditing.

## Generate tables and plots

```bash
python3 -m venv .cache/analysis
.cache/analysis/bin/python -m pip install -r threshold-kms/postprocess/requirements.txt
.cache/analysis/bin/python results/reproduce.py --output results/derived
```

Pre-rendered files are available under `preview/`. Choose a new output path on subsequent runs. Output contains all grouped metrics
in CSV/Markdown and three PDF/PNG/SVG figures per collection, each with CSV/JSON
plot values. The distributed nonlinear figure includes complete measured
verification CPU and time from challenge to decision, with later withdrawals
shown separately. Numerical source JSON for CPU and timing is also exported.

| Input | Contents |
| --- | --- |
| `workflow/observations.csv` | Per-case stage/metric/unit/value observations |
| `workflow/summary.json` | Grouped statistics and explicit measurement limits |
| `workflow/receipt-partition.csv` | Transaction partition and decision endpoints |
| `diagnostics/paired-observations.csv` | Paired methods, order and separate warm-ups |
| `setup.json` | Measurement configuration and hardware scope |
| `distributed/cpu-inputs/` | Retained process records needed to reconcile CPU sums |

The distributed observations use four `n2d-standard-4` hosts, under one cloud
project, in the regions recorded in `distributed/setup.json`. The local and cloud
runs differ in hardware, deployment, timing scope and full-case repetition count.
Their differences do not isolate the effect of geographic distance. Three cloud
cases per configuration do not establish latency tails or failure probabilities.
Read [metric definitions](../docs/METRICS.md) before comparing quantities.

Original CSV source references identify the measurement records from which the
numbers were exported. They are provenance labels, not paths expected to exist
in this public collection. For a new end-to-end execution, use
[local reproduction](../REPRODUCE.md) or [Google Cloud](../distributed/GOOGLE-CLOUD.md).
