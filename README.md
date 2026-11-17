# VC-FHE proof of concept

This repository contains the VC-FHE proof of concept for verifying computations performed by an external operator over encrypted user data while allowing data owners to control who can decrypt accepted results. The evaluation uses network Quality of Experience (QoE) as a case study, focusing on aggregating users' video ratings and assessing whether video sessions in a selected geographic area meet a quality target. These tasks involve individual records that may contain sensitive information.



The implementation includes smart contracts, FHE executors, threshold-KMS adapters, Docker Compose services, Google Cloud orchestration, tests, and measurement tools. The supported end-to-end configuration uses [TFHE-rs](https://github.com/zama-ai/tfhe-rs) for encrypted computation, four [Besu](https://github.com/besu-eth/besu) validators running QBFT, and four [Zama KMS](https://docs.zama.org/protocol/protocol/overview/kms) participants for distributed key generation and threshold decryption. The workflow covers result verification, dispute settlement, and owner-authorized result release.


The [Google Cloud measurements](results/distributed/README.md) and [numerical reproduction guide](results/README.md) are available for independent analysis. See [parameter scope](docs/EXPERIMENTS.md#parameter-scope) for the evaluation objectives and [security scope](docs/SECURITY.md) for confidentiality requirements.


## Repository map

| Directory | Contents |
| --- | --- |
| `docs/` | Architecture, protocol flows, security assumptions, experiment design, metric definitions, and validation evidence |
| `threshold-kms/` | End-to-end experiment runner, linear aggregate verifier, Zama KMS adapters, on-chain rules for owner-authorized decryption, and result validation and analysis |
| `distributed/` | Terraform provisioning for Google Cloud, communication between hosts, experiment orchestration, result collection, evidence preservation, and recovery |
| `fhe-pod/` | Nonlinear circuit compiler, FHE execution, audit workers, dispute contracts, and component tests |
| `BN254-Signatures/` | BLS signatures and homomorphic commitments for linear aggregates, with Solidity contracts, tests, and component benchmarks |
| `output-binding-lhs/` | Rust prototype and tests for linear homomorphic signatures and commitments over the scalar field |
| `contracts/` | Standalone Solidity registry for commitments to partial and final encrypted sums |
| `network/` | Besu QBFT genesis and validator configuration, contract deployment utilities, and network checks |
| `explorer/` | Read-only web dashboard for blocks, transactions, linear aggregate commitments, and nonlinear disputes |
| `formal/` | Lean 4 protocol models, 70 machine-checked lemmas and theorems, and a documented mapping to contract and KMS source code |
| `datasets/` | Input dataset documentation, downloaders, and preprocessing tools, including those for STAV360 and 5G-QoERA |
| `Anatel/` | Full and simplified QoE demonstrations inspired by Anatel's RQUAL indicators |
| `toolkit/` | Command-line expression compiler, supported operations, and QoE examples |
| `examples/` | Arithmetic trace walkthrough and linear application examples for source inspection |
| `scripts/` | Documentation link checks, checks on the public distribution, and SHA-256 inventories for retained experiment files |
| `results/` | CSV measurements from the [Google Cloud evaluation](results/distributed/README.md) and [local runs](results/local-archive/), with summary statistics, plots, and scripts to reproduce the numerical analysis offline |


## Processing Encrypted QoE Data with Verifiable Results

Quality of Experience (QoE) describes service quality from the user's perspective. Network providers can use QoE measurements to assess video quality across sessions or geographic areas and identify where service improvements may be needed. However, individual ratings and location-associated scores may reveal sensitive information about users. VC-FHE addresses these concerns by enabling predefined computations over encrypted records, verifying computation results, and allowing data owners to control who can receive those results.

### For instance: Assessing video quality in a geographic area

Consider a network provider that wants to determine whether at least 95% of video sessions in a selected geographic area have a mean opinion score (MOS) above 2.0. The selected-area experiment evaluates this question using session quality scores and geographic-cell identifiers. Both the score threshold and the required percentage can be configured for the assessment.

1. **Data encryption and authorization.** Data owners encrypt each session's score and geographic-cell identifier and approve the requested computation. The target area is public and corresponds to a cell on a 0.01-degree latitude/longitude grid.

2. **Computation over encrypted data.** The operator compares encrypted cell identifiers with the target area, counts the matching sessions, and determines how many have scores above the threshold. Cell membership, scores, and intermediate counts remain encrypted throughout the computation. The result is an encrypted 1 if at least 95% of the sessions in a nonempty selection exceed the threshold, or an encrypted 0 otherwise. A result of 0 may also indicate that no input records belong to the selected area.

3. **Verification of computation results.** Auditors independently repeat the computation over encrypted data to determine whether the operator executed it correctly. If a discrepancy is detected, a dispute may be initiated. Adjudicators then recompute the disputed operation without decrypting its inputs or output. This process relies on timely honest auditing, the availability of computation data, and a sound adjudicator quorum.

4. **Authorized result disclosure.** After the computation result has been verified and finalized, all contributing data owners approve the exact decryption request for the designated recipient. The network provider, or another authorized recipient, can then obtain the final decision without accessing individual session records, which remain encrypted.

The all-sessions experiment checks whether at least 95% of the sessions in each
input set have a mean opinion score (MOS) above 2.0. Both quality checks use
model-derived scores based on simulated 5G performance along real mobility
traces, as described in the [5G-QoERA paper](https://telematics.poliba.it/wp-content/uploads/publications/2025/wcnc25boffetti.pdf).
For the regional check, the circuit receives an encrypted score and an encrypted
geographic cell identifier as its only per-session inputs. The linear experiment
verifies the encrypted sum of subjective ratings of 360° videos from
[STAV360](https://github.com/SLG-European-Projects/STAV360). After authorized
decryption, the recipient divides the sum by the public number of ratings to
obtain the mean. The [experiment guide](docs/EXPERIMENTS.md#inputs-and-workload-meaning)
describes input selection and all three computations.


## Choose a starting point

| Goal | Entry point |
| --- | --- |
| Understand the roles and acceptance rules | [Architecture](docs/ARCHITECTURE.md) |
| Understand challenge payments and incentive conditions | [Incentives and proofs](docs/INCENTIVES.md) |
| Follow acceptance, dispute and authorization transitions | [Protocol flows](docs/PROTOCOLS.md) |
| Inspect assumptions and their supporting evidence | [Evidence map](docs/EVIDENCE.md) |
| Choose a reproduction target and interpret the experiment | [Experiment design](docs/EXPERIMENTS.md) |
| Verify the protocol model proofs | [Lean proofs](formal/README.md) |
| Inspect the experiment without starting services | `./run-poc.sh --list` |
| Run on one Docker host | [Local reproduction](REPRODUCE.md) |
| Run across Google Cloud regions | [Distributed overview](distributed/README.md) and [runbook](distributed/GOOGLE-CLOUD.md) |
| Verify retained numerical results and regenerate plots | [Results](results/README.md) |
| Inspect the latest Google Cloud results and plots | [Cloud results](results/distributed/README.md) |
| Interpret timers, CPU, gas and communication | [Metrics](docs/METRICS.md) |
| Develop or run regression checks | [Development](docs/DEVELOPMENT.md) |
| Understand assumptions and handle private state | [Security and limitations](docs/SECURITY.md) |

The current scientific results are the distributed collection. `results/local-archive/`
retains a separate local experiment for reference. The two collections must not be
mixed. Start with offline numerical verification or the Lean models if you do not
intend to create services. Fresh execution requires the external dependencies
and dataset access stated in the guides.

## Local execution

Run from this directory on Linux, macOS or WSL2, with Python 3.10+, Git and Docker
with Compose v2. The launcher checks supported dependencies and prepares isolated
build and plotting environments. See the reproduction guide before executing:

```bash
./run-poc.sh --preflight
./run-poc.sh --readiness
./run-poc.sh
```

The preflight inspects prerequisites. The readiness command executes a separate
largest-case pilot. The last command runs the complete experiment and derives its
results. It is not a quick demonstration. Check available disk and Docker memory.

Independent routes are `./run-linear.sh` and `./non-linear.sh`. Add `--readiness`
to select their pilots. `run-nonlinear.sh` is an alias. Each invocation creates a
new run directory and threshold keyset. Existing policy counters and identities
are retained. Do not reset the chain or replay a completed release.

## What is implemented

- Linear aggregation: owner-bound signatures and commitments, record admission,
  aggregate authentication and recipient-side checks.
- Nonlinear computation: explicit circuits, canonical ciphertext replay,
  authenticated traces, bonded challenges, bisection and certified leaf decisions.
- Output authorization: all contributing owners approve the statement and the
  exact recipient-bound request after finality. On-chain one-use slots and
  cumulative record counters constrain release.
- Distributed execution: role-local identities, authenticated transport,
  homogeneous CPU admission, cross-host ciphertext checks and source-bound images.
- Measurement: separate paired comparisons, warm-ups, complete workflows,
  process CPU, elapsed timers, transaction receipts and communication scopes.

Local full execution collects 480 paired comparisons, 18 warm-ups and 45 full
workflows. Distributed execution retains the same comparisons and warm-ups with
27 full workflows. A smoke run cannot substitute for either complete design.


The source directory is self-contained and can be copied without Git history.
Third-party dependencies and input datasets are acquired during preparation.
Private identities, cloud settings, previous live runs and build caches are not
part of this distribution. [Dataset provenance](datasets/README.md) and
[dependency notices](THIRD-PARTY.md) describe the external inputs.

The project code is distributed under [MIT](LICENSE). Upstream components and
input datasets retain their own terms.
