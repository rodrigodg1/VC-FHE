# Local reproduction with Docker

Run every command below from the repository root. Use one local campaign at a
time. Linux, macOS and WSL2 are supported host environments. Native Windows is
not an execution target for the Rust FHE backend. On Windows, use a WSL2 shell
with Docker integration and keep the source on the Linux filesystem.

For the distinction between numerical replay, a fresh execution and original
raw-evidence validation, read [experiment design](docs/EXPERIMENTS.md). The local
45-case design is separate from the retained 27-case geographic collection.

## Requirements

| Requirement | Purpose |
| --- | --- |
| Python 3.10+ with `venv` and `pip` | Controller, validation and numerical analysis |
| Git and internet during preparation | Pinned upstream sources and datasets |
| Docker engine and Compose v2 | Besu, KMS and FHE services |
| Writable complete source directory | Source-bound builds and per-run outputs |

The launcher supports Homebrew on macOS and apt on Debian/Ubuntu for missing
prerequisites. Homebrew or administrator privileges must already be available.
It checks the Docker daemon and prepares a pinned Matplotlib environment. Rust
and Node dependencies are built inside the campaign image. Inspection commands
install nothing. Docker Desktop may need to be started separately.

The runner requires at least 20 GiB free on the workspace filesystem at startup.
This is a reserve, not a bound on total storage. Docker storage and memory limits
are separate. No minimum physical RAM or completion-time guarantee has been
established for an arbitrary machine. The native build, threshold setup and
complete experiment can require substantial time and disk space.

## Inspect first

```bash
./run-poc.sh --help
./run-poc.sh --list
./run-poc.sh --preflight
```

`--list` shows the design. `--preflight` checks available tools and policy-state
layout without installing dependencies or creating a lineage. It does not prove
live chain capacity, dataset availability or cryptographic completion.

## Pilot, then full execution

| Scope | Largest-case pilot | Complete experiment |
| --- | --- | --- |
| Linear | `./run-linear.sh --readiness` | `./run-linear.sh` |
| Nonlinear | `./non-linear.sh --readiness` | `./non-linear.sh` |
| Combined | `./run-poc.sh --readiness` | `./run-poc.sh` |

Inspect the pilot's final validation before launching the full design. The full
command does not automatically run or verify a previous pilot. Both use real
cryptographic and authorization operations. Pilot releases also consume policy
capacity. `run-nonlinear.sh` and `run-nonlinear-bounty.sh` select the nonlinear route.

| Local full scope | Measured pairs | Separate warm-ups | Full workflows |
| --- | ---: | ---: | ---: |
| Linear, 10/16/27 records | 300 | 6 | 15 |
| Two nonlinear workloads, 16/32/50 records | 180 | 12 | 30 |
| Combined | 480 | 18 | 45 |

The nonlinear workloads are `regulatory_qoe_compliance` and
`regional_qoe_compliance`. Each configuration selects five full cases in advance.
The audit/disclosure windows remain 120 seconds. Infrastructure timeouts do not
change those contract windows.

The default profile uses Test parameters and one FHE/KMS execution thread where
pinned by the profile. This profile exercises the complete functional PoC with
public research inputs, without a simulator or full-key fallback. See
[parameter scope](docs/EXPERIMENTS.md#parameter-scope) for the evaluation objectives
and interpretation of its measurements.

## Installed services and state

The launcher starts the Compose services and configures their network. Do not
manually deploy a second chain before it. The local Besu template is
`network/validators-besu/docker-compose.besu.yml` (Besu 25.3.0, chain ID 46853,
two-second QBFT blocks). RPC port 8550 belongs to the local development network;
keep it isolated. Participant signing identities, KMS shares and consumed policy
state are not public configuration samples.

A successful pilot validates its own largest cases and source/profile bindings.
It does not bound full-run duration or storage growth. Preserve enough capacity
for build layers, keys, ciphertexts, validation and derived outputs.

## Initial state and progress

A genuinely empty installation initializes its policy and identities. Later
invocations preserve that lineage and its cumulative counters. Partial local
state or orphaned Besu volumes prevent automatic initialization. Do not use
`--new-policy-lineage` as a recovery step; the public wrappers reject it.

Each invocation creates a new threshold keyset. A combined run shares its keyset
across both paths. Optional `--run-dir PATH` names a new run directory. An existing
incomplete run is not silently resumed. `--timeout SECONDS` is an infrastructure
stage limit, not an extension of protocol deadlines.

The console reports setup, owner encryption, paired comparisons and full
workflows separately. Inspect the printed run directory and
`reports/progress-owner.jsonl` / `reports/progress-evaluation.jsonl`. Progress
percentages count work items; they do not predict remaining time. Recipient
release alone does not mark an entire case complete.

## Validate and analyze

Replace `RUN_ID` with the directory printed by your completed execution:

```bash
./run-poc.sh --check --run-dir threshold-kms/runs/RUN_ID
./run-poc.sh --postprocess-only --run-dir threshold-kms/runs/RUN_ID
```

For an independently executed half, use its matching launcher for `--check`.
The analysis route reads the selected scope from the run. Raw verification needs
the original sources, fixtures, executables, receipts and seal. A numerical CSV
collection is not a substitute for these files.

| Location | Meaning |
| --- | --- |
| `threshold-kms/runs/RUN_ID/` | Original configuration, state, logs, reports, fixtures, executable records and seal |
| `threshold-kms/composites/RUN_ID-workflow/` | Derived analysis, separate from the measured source |
| `workflow/observations.csv`, `workflow/summary.json` | Per-observation values and grouped summaries |
| `diagnostics/`, `diagnostic-review.json` | Paired-data checks and their bound review |
| `setup-review.json`, `setup-review.md` | Hardware/configuration evidence and scope |
| `metrics.csv`, `METRICS.md` | All grouped metrics, units and sample counts |
| `figures/` | PDF/PNG/SVG plots and the associated CSV/JSON values |
| `analysis-package.json` | Hash inventory of derived outputs |
| `postprocess-status.json` | Analysis status, separate from experiment completion |

A complete derivation reports `results-ready`. `--manual-review` writes a
source-bound diagnostic review template and stops before the final derivation.
Use `--diagnostic-review PATH` after completing that review. Automated review
checks recorded diagnostic conditions; it does not claim visual inspection.

If an earlier derived directory is incomplete, retain it and select a new direct
child of `threshold-kms/composites/` using `--derived-dir PATH`. Do not rerun the
cryptographic experiment because plotting failed. See
[analysis internals](threshold-kms/postprocess/README.md).

## Interruptions

Preserve the run directory, `threshold-kms/.policy-state/`, matching Besu volumes,
identities, KMS state and build records. Interrupting the host runner does not
necessarily stop every container. Inspect actual process/container state first.
Never reset counters, delete volumes or repeat a consumed release to repair a run.

Recovery of the default bounty-v2 local campaign is not yet validated. The older
[V3 tools](threshold-kms/recovery/README.md) apply only to their earlier profiles.
Preserve the interrupted run for inspection. Do not use them as an automatic
resume command for the current deployment.

## Reproduce retained numbers without services

Use [the numerical collection](results/README.md). Its checksum and statistical
checks need only Python. Rendering requires the pinned plotting dependencies.
This route performs no blockchain transaction, decryption or cloud operation.
