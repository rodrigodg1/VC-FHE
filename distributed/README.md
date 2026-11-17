# Distributed reproduction on Google Cloud

This directory deploys and observes real FHE computation, four threshold-KMS
participants and four Besu QBFT validators across four Google Cloud regions.
It provides source-bound preparation, functional checks, measurement collection,
validation, preservation and restricted recovery procedures.

The supported configuration uses **Test parameters for functional PoC evaluation**
with public research inputs. [Parameter scope](../docs/EXPERIMENTS.md#parameter-scope)
explains the evaluation objectives and how to interpret the measured costs.
All hosts in the example are administered through one cloud project. Geographic
distribution alone does not establish independent administration, production
availability or Byzantine liveness.

## Guides

- [Google Cloud setup and Terraform](GOOGLE-CLOUD.md)
- [Detached cloud controller](cloud_results/README.md)
- [Operation and recovery](OPERATIONS.md)
- [Storage and private data](STORAGE.md)
- [Metric definitions](../docs/METRICS.md)
- [Numerical results](../results/README.md)

Run commands from `VC-FHE-GITHUB/`. Replace uppercase placeholders privately.

## Roles and topology

The `four-hosts` layout has 21 logical roles. Each host contains one validator,
one KMS participant and one data owner. Additional roles are assigned as follows
by `topology.py` and the example configuration:

| Host | Example region / zone | Additional roles |
| --- | --- | --- |
| 1 | `us-central1` / `us-central1-a` | Operator and protocol coordinator |
| 2 | `europe-west4` / `europe-west4-a` | Auditor 1 and adjudicator 1 |
| 3 | `asia-southeast1` / `asia-southeast1-b` | Auditor 2 and adjudicator 2 |
| 4 | `australia-southeast1` / `australia-southeast1-a` | Auditor 3, adjudicator 3 and recipient |

The [measured setup comparison](../docs/EXPERIMENTS.md#measured-deployment-and-fresh-template)
identifies differences from the public template. No historical live resources or
private predecessor state are supplied by this repository. Measurements belong to the CPU, zone,
image and execution profile recorded in their own setup descriptors.

The optional fifth VM controls the experiment and validates evidence. It is
not a fifth validator or KMS participant, and is distinct from the protocol
coordinator on host 1. Co-located roles share CPU, memory and host failures.
The configuration also recognizes a dedicated-role layout, but the full
cloud-controller route requires `four-hosts`.

Each participant creates its signing identity on its assigned host. KMS private
vaults remain isolated. Public identities, certificates and ciphertexts cross
authenticated endpoints with mTLS, pinned certificates and SHA-256 checks.
The coordinator does not collect participant private keys. Auditors and
adjudicators recompute public ciphertext operations without decryption.

Final-output release requires owner authorization, an exact recipient-bound
request, an unused slot and cumulative record-quota checks. Each KMS core checks
the fixed reservation block and hash through the validators, requiring three
identical canonical responses. The configured recipient response threshold is
three and the adjudicator threshold is two. These are different checks and must
not be substituted for one another. Contract windows remain at least 120 seconds.

## Execution design

`experiment_plan.py` fixes the full design before measurement:

| Component | Sizes and repetitions | Total |
| --- | --- | --- |
| Linear paired comparisons | 100 at each of 10, 16 and 27 records | 300 |
| Nonlinear paired comparisons | 30 for each of two workloads at 16, 32 and 50 records | 180 |
| Warm-ups | Separate from measured pairs | 18 |
| Complete linear workflows | Repetitions 0, 49 and 99 at each size | 9 |
| Complete nonlinear workflows | Repetitions 0, 14 and 29 for each workload and size | 18 |

The nonlinear workloads are `regulatory_qoe_compliance` and
`regional_qoe_compliance`. Their selected cases retain early, middle and terminal
faults, baseline computations, disputes and authorized output recovery.
A complete workflow is more than a mined transaction or a released output.

A normal new execution provisions hosts, enrolls participants, configures the
chain and policy, runs real PRSS/preprocessing/DKG, encrypts assigned owner
inputs, checks cross-host ciphertext-byte repeatability, then measures the
paired and full-workflow grid. Validation and preservation follow computation.
The byte-repeatability admission probe is not a measured repetition.

The owner fixtures are public research inputs. Each owner encrypts records
assigned to its identity. This is not a private production ingestion service.
Setup, comparison work and complete workflows have separate records. Three
full observations per configuration do not support tail-latency or failure-rate
claims. Timing and storage requirements must be measured and budgeted for the
complete design, not extrapolated from smoke success alone.

## Start with offline checks

```bash
./run-distributed.sh dependencies --check
./run-distributed.sh test
./run-distributed.sh plan
./run-distributed.sh prepare --output distributed/generated/example-plan
./run-distributed.sh audit-public
```

Use a new output directory for `prepare`. These commands do not create cloud
compute or run the cryptographic experiment. The dependency check reports missing
tools. Explicit `dependencies --install` installs supported controller tools and
may download packages or require OS privileges. Tests include Python, Node and
both recovery suites. Passing them is not evidence that a cloud run completed.

Continue with [project and image preparation](GOOGLE-CLOUD.md), then choose the
smoke or the [full cloud-controller route](cloud_results/README.md). Preparation,
functional smoke, full execution and recovery are separate operations.

## Completion criteria

Do not declare success from process exit alone. Require all of the following:

1. The exact measured grid and distinct warm-ups match the frozen plan.
2. Every full case has matching coordinator completion, application evidence,
   native validation, finality, recipient output and required dispute evidence.
3. Source, image, binary, input and execution-context hashes match their records.
4. Release requests, one-use slots and cumulative counter deltas reconcile without
   duplicates. Multiple segments are validated separately and composed explicitly.
5. Metric denominators, missing values and timing boundaries remain identifiable.
6. Preserved objects have checksum/readback receipts, or retained disks/snapshots
   have their accurately stated preservation scope. A snapshot is not a file audit.
7. Small delivered files pass their manifest checks. Shutdown is confirmed through
   current provider state for the exact VM identities.

A failed backup does not undo completed workflows. It does block a claim that
all preservation succeeded. A failed execution must retain its original status,
logs, source closure and consumed state. No failed attempt is silently replaced.

## Source map

| Files | Responsibility |
| --- | --- |
| `cli.py`, `topology.py`, `experiment_plan.py` | CLI, role placement and immutable grid |
| `gcp.py`, `cloud_setup.py`, `price_quote.py`, `budget.py` | Infrastructure, permissions, quotas and admission |
| `image.py`, `gce_image.py`, `cloud_build.py`, `runtime.py` | Bound image preparation and isolated execution adapters |
| `launch.py`, `remote.py`, `status.py` | Execution, remote transport and observation |
| `probe.py`, `metrics.py`, `supplement.py`, `delay_metrics.py` | Telemetry and derived observations |
| `collect.py`, `cloud_archive.py`, `archive_worker.py` | Evidence collection and private backups |
| `cloud_results/` | Detached cloud controller, validation, bounded transfer and cleanup |
| `maintenance/workflow-recovery/` | Restricted continuation before any completed release |
| `maintenance/completed-prefix-recovery/` | Reconciled continuation after a completed prefix |
| `tests/` | Offline regressions, including synthetic and mocked cases |

Public documentation contains generic examples only. Private configurations,
resource identities, access tokens, Terraform state, raw logs, keys and backups
belong in ignored restricted storage. See [data handling](STORAGE.md).

