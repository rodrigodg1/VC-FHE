# Experiment design and independent reproduction

There are three distinct reproduction targets. Choose one before running commands.

| Target | Guide | Output / acceptance |
| --- | --- | --- |
| Recompute statistics from retained observations | [Numerical reproduction](../results/README.md) | Hash/count/statistic checks; regenerated tables and plots; no services |
| Execute a new full functional experiment locally | [Local guide](../REPRODUCE.md) | New original evidence/seal; 480 measured pairs, 18 warm-ups, 45 full cases |
| Execute a new geographic functional experiment | [Cloud setup](../distributed/GOOGLE-CLOUD.md), then [controller](../distributed/cloud_results/README.md) | New source/image-bound evidence; 480 pairs, 18 warm-ups, 27 full cases and verified delivery |

The public package includes the source for fresh execution and numerical exports
for analysis. It excludes old private keys, raw ciphertexts, native binaries,
chain databases and consumed release state. Therefore an external reader can
recompute published statistics or run a new experiment, but cannot reconstruct
the original execution's full cryptographic validation solely from this package.
New measurements need not reproduce identical wall times, ciphertexts or hashes.

## Parameter scope

The PoC evaluates encrypted computation, output verification, dispute settlement
and owner-authorized threshold release using real FHE and KMS operations. The
upstream Test parameter set reduces the cryptographic workload for functional
testing. It is sufficient to exercise these workflows on public research inputs.
Running Default is not a prerequisite for this functional evaluation.

Proposed methods and their baselines use the same cryptographic parameter profile
and ciphertexts within each comparison. Timings and communication costs describe
that measured configuration. Costs for other parameter sets require separate
measurements. The cryptographic assumptions supporting the protocol guarantees
remain distinct from the functional results. See [security scope](SECURITY.md)
for the parameter requirements of confidentiality claims.

## Inputs and workload meaning

[Pinned dataset acquisition](../threshold-kms/campaign/datasets.py) checks exact
SHA-256 values before use. STAV360 uses revision
`ef4dd1ea35f275d4240b5886dcc0e372de73d330`; 5G-QoERA uses
`3add3121ded7a31f1434e863073917772993b74b`. See [dataset terms](../datasets/README.md).
For QoERA the digest is checked **after** deterministic tab-to-comma conversion.
A mismatch preserves an existing input and aborts; it is not permission to update
the expected digest. No raw rating files are redistributed here.

| Workload | Dataset / representation | Output and admission |
| --- | --- | --- |
| Linear ratings aggregate | STAV360 subjective ratings, 1–5 | Encrypted SUM for 10/16/27 users; mean obtained after authorized recovery by dividing by public count |
| `regulatory_qoe_compliance` | QoERA modeled MOS, rounded to thousandths | Bit indicating that at least 95% of 16/32/50 records exceed encoded MOS 2000 |
| `regional_qoe_compliance` | Same scores plus encrypted geographic-cell identifier | Same threshold over a public target cell; an empty selection returns zero |

The fixed panels are disjoint; selected-area panels include records from two
cells. The cell grid has 0.01-degree latitude/longitude resolution. MOS and cell
identifiers are encrypted, not user identifiers or precise coordinates. QoERA
contains simulated/model-derived performance alongside real mobility/location
inputs, not direct subjective observations equivalent to STAV360 ratings.

Repetitions re-encrypt the same selected records using fresh randomness; they do
not sample new users or sessions. Both methods within a pair use the same
ciphertexts. The compiler admits explicit unsigned-64-bit circuits and public
bounds. Supported operations are defined in
[fhe-pod/scripts/micro-isa.mjs](../fhe-pod/scripts/micro-isa.mjs); expression-toolkit
support is a separate front end, not a claim of arbitrary encrypted programs.

The [compliance circuit correctness note](compliance-circuit-correctness.md)
defines the global and regional predicates, the unsigned-arithmetic bounds and
the preservation argument for counts and padding. It distinguishes circuit
semantics from the assumptions required for trace acceptance.

## Counts, order and baselines

| Design element | Local | Geographic |
| --- | ---: | ---: |
| Linear pairs: 100 per size, three sizes | 300 | 300 |
| Nonlinear pairs: 30 per workload/size, six configurations | 180 | 180 |
| Two warm-ups per configuration, excluded from paired statistics | 18 | 18 |
| Full cases per configuration | 5 | 3 |
| Complete full-case grid | 45 | 27 |

Full cases are selected in advance. For the distributed grid, linear repetitions
are 0/49/99 and nonlinear repetitions 0/14/29. An authorized release is one
milestone, not the completion of an entire case. Nonlinear cases also include
honest acceptance, reference/baseline work and challenged faults at early, middle
or terminal instructions. The 27 full cases include 18 nonlinear disputes, not
27 disputes. Check [poc_plan.py](../threshold-kms/campaign/poc_plan.py) and
[experiment_plan.py](../distributed/experiment_plan.py).

Linear baseline: ordinary BLS verification on ciphertext vectors plus encrypted
reaggregation. Nonlinear baseline: two independent full recomputations with a
whole-execution certificate. Proposed nonlinear verification: one full audit,
plus instruction certification when challenged. Comparing disputed proposed work
with the measured correct-task baseline is not a measured baseline-rejection test.
Order alternates within blocks of two pairs. This controls one execution-order
factor but does not prove independence, stationarity or equal host performance.

## Measured deployment and fresh template

The retained [setup descriptor](../results/distributed/setup.json) records four
`n2d-standard-4` protocol hosts: `us-east4-c`, `europe-west4-a`,
`asia-southeast1-b`, `australia-southeast1-b`. The admitted measured CPU family was
AMD Milan. The current configuration example instead defaults to `n2-standard-4`
and Intel Ice Lake, with a different first region and last zone. It is a generic
provisioning template, **not** the measured setup descriptor.

To target the measured machine family in a **new private configuration**, set
`host_machine_type` to `n2d-standard-4`, `min_cpu_platform` to `AMD Milan`, and
review the four zone/region pairs against `setup.json`. Do not edit the public
example into a private deployment file. CPU admission, quotas, image compatibility
and cross-host byte-repeatability checks still apply. Matching machine names
alone does not establish equivalent conditions or identical performance.

The protocol uses Test TFHE-rs 1.6.1, pinned upstream KMS v0.13.20, four Besu
validators with a two-second block period, 120-second nonlinear windows, three
required KMS responses and two adjudicator signatures. Pinned dependency locks,
image/binary hashes and source descriptors qualify every actual run. Dependency
source versions and the formal-model toolchain are described in
[development](DEVELOPMENT.md) and [formal verification](../formal/README.md).

## Validation and interpretation

Require exact design coverage; distinct warm-ups; source/input/binary hashes;
correct recipient/reference outputs; native contract/request/slot/counter evidence;
and complete dispute and payment evidence. For segmented recovery, validate each
segment under its own bindings, then exact composed coverage and counter history.
Never treat a failing original attempt as a passing uninterrupted execution.

Derived numeric checks require correct grouping, units, actual sample counts,
finite values and matching hashes. Mean/sample SD for three full cases is a small
sample description, not a population significance claim or tail-latency estimate.
Do not sum overlapping wall intervals or process memory peaks. CPU, remote
request/response time, mined block intervals and gas have different boundaries.
[Metrics](METRICS.md) and the [data dictionary](../results/DATA-DICTIONARY.md)
define these distinctions.

The preserved data support functional output correctness and measured costs in
the configuration described under [parameter scope](#parameter-scope). They do
not establish spontaneous honest audit participation, independent administration,
fault rates, or the causal effect of geographic separation. KMS/decryption
diagnostics are excluded from verification-cost comparisons.
Read [validation status](VALIDATION.md) before
interpreting a successful offline check as a new full experiment.
