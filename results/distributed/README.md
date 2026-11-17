# Google Cloud results

This directory retains the latest completed distributed PoC collection: 480
measured pairs, 18 separate warm-ups and 27 full cases across nine configurations.
The full cases combine a ten-case completed prefix and a 17-case continuation.
They are not 27 new executions. The setup used four `n2d-standard-4` hosts in
`us-east4`, `europe-west4`, `asia-southeast1` and `australia-southeast1`, under
common administration. See [setup.json](setup.json) for the measured configuration.

## Main plots

These plots use the retained observations. Each has PDF, PNG and SVG versions,
plus CSV and JSON values, in [the generated preview](../preview/distributed/).

| Plot | What it measures |
| --- | --- |
| [Linear verification](../preview/distributed/linear-cost.png) | Paired off-chain verification and proposed admission/result-submission gas |
| [Nonlinear work and decision timing](../preview/distributed/nonlinear-work.png) | Paired elapsed time, verification CPU including context and full auditing, and blocks until rejection followed by later withdrawals |
| [Workflow gas](../preview/distributed/workflow-gas.png) | Gas by stage, including authorization and settlement |

The nonlinear preview includes a broader CPU accounting than the FHE-process-only
plot below. It also separates the decision from subsequent withdrawals. Both use
the same measured cases. A CPU sum is not elapsed workflow time, and block counts
include protocol waiting periods.

## Supplementary plots

These five plots are unchanged copies of the retained outputs. The corresponding
CSV and JSON files preserve their plotted values and measurement definitions.
PDF and SVG versions are available in [figures/](figures/).

| Plot | Scope |
| --- | --- |
| [Linear paired verification](figures/linear-paired-verification.png) | 100 measured pairs per size, with sample standard deviations |
| [Recipient bytes](figures/linear-recipient-bytes.png) | Aggregate payload and baseline serialization model, without cached inputs or authorization/KMS traffic |
| [Nonlinear paired recomputation](figures/nonlinear-paired-recomputation.png) | 30 measured pairs per configuration, excluding certification, chain waits and decryption |
| [FHE-process CPU by role](figures/nonlinear-role-fhe-cpu.png) | Separate honest-audit, baseline and challenged-instruction work; excludes context certification and other controllers |
| [Settlement residuals](figures/nonlinear-settlement-residuals.png) | Rewards and penalties after the stated measured costs; not profit or evidence of sustained participation |

## Paired diagnostics

The nine diagnostic plots retain time-series, distribution and dependence checks.
The [diagnostic summary](diagnostics/summary.json) records the statistical method,
conditional intervals, temporal flags and review status. Warm-ups are recorded
separately and are excluded from measured means. No valid outliers were removed.

| Workload | Configuration plots |
| --- | --- |
| Linear ACR | [10](diagnostics/linear-acr-10.png), [16](diagnostics/linear-acr-16.png), [27](diagnostics/linear-acr-27.png) |
| Regulatory QoE | [16](diagnostics/regulatory_qoe_compliance-16.png), [32](diagnostics/regulatory_qoe_compliance-32.png), [50](diagnostics/regulatory_qoe_compliance-50.png) |
| Regional QoE | [16](diagnostics/regional_qoe_compliance-16.png), [32](diagnostics/regional_qoe_compliance-32.png), [50](diagnostics/regional_qoe_compliance-50.png) |

## Numerical inputs and checks

- [Observations](workflow/observations.csv) and [summary](workflow/summary.json):
  8,392 rows and 1,504 grouped metrics.
- [Paired observations](diagnostics/paired-observations.csv): all 480 measured
  pairs and 18 warm-ups, including execution order.
- [Receipt partition](workflow/receipt-partition.csv): transaction costs and
  decision endpoints with opaque account/transaction identifiers.
- [Settlement economics](workflow/economics.json): 18 challenged cases, measured
  transfers and fees, and explicit unpriced costs.
- [CPU inputs](cpu-inputs/): compressed process measurements for the same 27
  cases, using logical host/role names and opaque identifiers.
- [Case origins](case-origins.json): segment membership and source-record hashes.

From the repository root:

```bash
python3 results/reproduce.py --collection distributed
python3 scripts/check-public.py
```

See [offline reproduction](../README.md) to regenerate the three main plots and
all metric tables. The supplementary plots and diagnostics are retained outputs,
with their numerical inputs included. [collection.json](collection.json) binds
the files to SHA-256 hashes. It does not replace the original execution seals.

## Data included in this copy

The collection contains measurements, statistics and plots. It excludes owner
input records, keys, credentials, project/account identifiers, network addresses,
Terraform state, chain databases and raw runtime logs. Account and transaction
references use stable opaque labels, and source references use relative labels.
No mapping back to private identifiers is included. Image and PDF metadata were
also inspected before copying the retained plots.

The results describe this PoC configuration. They do not establish secure-profile
performance, independent administration or the causal effect of geographic
distance. Three full cases per configuration do not estimate latency tails.
Numerical reproduction does not revalidate the complete cryptographic execution.
