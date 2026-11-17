# Assumptions and private state

We evaluated VC-FHE as a proof of concept in a test environment using public
research datasets and the TFHE-rs `Test` parameter set. The
[functional evaluation](EXPERIMENTS.md#parameter-scope) covers computation over
encrypted inputs, result verification, dispute settlement, and owner-authorized
threshold decryption. The reported costs apply to the evaluated test
configuration.

Use the `Test` profile only with public or synthetic inputs. Production
deployments that process confidential data require cryptographic parameters
selected for the intended security level and must satisfy the protocol
assumptions below.

Acceptance assumes protocol-compliant owner inputs, the specified signature and
commitment properties, a live covering auditor, available authenticated evidence,
canonical FHE execution, and a sound adjudicator quorum. The system authenticates
computation over admitted inputs. Assessing the accuracy of an input measurement
requires separate evidence. Correctness checks and statistical measurements have
different scopes.

## Running the proof of concept

The local Besu network uses public development accounts and should run in an
isolated environment. If a run is interrupted, preserve its chain state and
authorization records, which track prior releases and usage limits. See the
guides for [local interruptions](../REPRODUCE.md#interruptions) and
[cloud recovery](../distributed/OPERATIONS.md#recovery-invariants).

Keep credentials, raw logs, and private run records out of public commits and
archives. The [storage guide](../distributed/STORAGE.md) explains which results
can be shared and which records require restricted storage.

## Evidence and reproduction

The [evidence map](EVIDENCE.md) explains the assumptions and evidence for each
protocol guarantee. The [Lean proofs](../formal/README.md) cover protocol models
and mathematical components. The [source correspondence](../formal/SOURCE_CORRESPONDENCE.md)
documents the reviewed mapping from the models to the Solidity and Rust code.

The [results guide](../results/README.md#check-the-numbers) explains how to
verify the published files and recompute the statistics. Revalidating an
original run requires its matching execution evidence.

## Reporting a problem

For public issue reports, include the affected version, a small synthetic
example, and the observed failure. Contact the maintainer privately about
sensitive issues, following the [repository security guidance](../SECURITY.md).