# Guarantees, assumptions and evidence map

This map applies to the source distributed here. Public data reproduction,
execution tests and mathematical verification establish different statements.
Use [validation records](VALIDATION.md) for dates and commands rather than
assuming every historical measurement used today's controller source.

| Property | Source entry point | Evidence | Necessary boundary |
| --- | --- | --- | --- |
| Authenticated linear aggregate | `BN254-Signatures/contract/MKLHS-Verification-v3.sol`, `threshold-kms/contracts/GroupedLinearVerification.sol` | Linear algebra lemmas; component tests; nine distributed full cases | Honest input preparation, signature/commitment binding and delivered-vector verification |
| Grouped conversion | `threshold-kms/src/compatible_fhe.rs`, `linear_release.rs` | Nine grouped-conversion lemmas; run validators | Fixed layout/ranges, FHE correctness and independent conversion checks; not proved by the linear contract |
| Explicit nonlinear dependencies | `fhe-pod/scripts/compliance-circuit.mjs`, `crates/tfhe-pod-demo/src/bin/circuit-executor.rs` under `fhe-pod/` | Lowering/dataflow tests and canonical replay | Supports the admitted operation set, not arbitrary source-language semantics |
| First-divergence localization | `fhe-pod/scripts/canonical-protocol.mjs` | `Canonical.first_difference_invalid`, `Bisection.detection_and_localization` | Authenticated structural/provenance checks, deterministic pinned evaluator, Merkle binding |
| Conditional rejection of invalid execution | `CanonicalBountyFHEDisputeGame.sol`, `CanonicalLeafVerifier.sol` under `fhe-pod/contracts/src/` | `Dispute.conditional_trace_soundness`; contract regressions; 18 measured disputes | Timely funded honest auditor coverage and sound adjudication remain assumptions |
| Bounty entitlement and funded reservations | Same game; `BountyTraceAvailability.sol` | Bounty settlement model, economics lemmas and contract balance tests | Active correct challenger; actual-cost bounds and live completion for positive surplus |
| Conditional finalization | Inherited reopening rules, spent challenger flags, certificate admission | `Liveness.eventual_finality` | Finite cohort, authenticated data, eventual productive inclusion and adjudication |
| Owner approval, no reuse and budgets | `threshold-kms/contracts/OnChainReleasePolicy.sol` | `Release.reachable_invariant`; authorization evidence validation | Stable owner-bound record IDs and one policy deployment; registration does not prove real-world ownership |
| Exact KMS request and output binding | `threshold-kms/src/onchain_release.rs`, `linear_release.rs`, `recipient_validation.rs` | Model interface `Release.OutputBound`; adapter/guard tests and retained release observations | Fixed finalized-state agreement and honest responder duties; reservation can precede delivery failure |
| Recovered nonlinear plaintext | Composition of canonical execution and release interfaces | `Composition.released_plaintext_correct`, `EndToEnd.nonlinear_plaintext_error_bound` | Binding, certification, coverage, task-level FHE and KMS correctness; failure probabilities not measured |
| Audit without extra decryption | Public executor/replay paths and restricted KMS executor build | `AuditPrivacy.public_transcript_noninterference`, `public_simulator_exists`; source correspondence | Public-only operation premise; metadata/output disclosure remains; confidentiality requirements in [security scope](SECURITY.md) |
| Distributed functional behavior | `distributed/runtime.py`, `worker.mjs`, image/source descriptors | Retained 480 pairs, 18 warm-ups and 27 full cases | Four geographic hosts, common administration, functional Test profile; [parameter scope](EXPERIMENTS.md#parameter-scope) |

All named Lean results and their exact types are indexed in
[formal/README.md](../formal/README.md) and
[formal/evidence/theorems.txt](../formal/evidence/theorems.txt).
The [source correspondence](../formal/SOURCE_CORRESPONDENCE.md) and its SHA-256
manifest bind the reviewed model-to-code mapping. The kernel checks proofs of
those model statements, **not** a compiler/executable refinement proof, a Solidity
bytecode proof, or a proof of external cryptographic hardness.

## Conditional soundness and privacy

For nonlinear execution, missing honest audit coverage is an explicit failure
event. The composed finite weighted probability model bounds incorrect recovery
by the sum of that event and binding, certification, FHE and KMS failures. It uses
no independence assumption and provides no numerical estimate of those risks.
Deterministically repeating a faulty FHE operation does not reduce its error.

The [incentive conditions](INCENTIVES.md) do not remove the coverage premise.
Agreement receives no bounty; a quiet workload can make costly fault-only auditing
unprofitable. Neither the contract nor commit/reveal proves independent work.

“No decryption during audit” does not imply zero information disclosure. Public
records, task metadata, ciphertext lengths, graph structure, timing, approvals and
authorized outputs remain visible to the relevant observers. The Test profile
exercises the functional audit and release paths. Confidentiality depends on the
parameter and protocol requirements in [security scope](SECURITY.md), separately
from the observed functional behavior.

## Historical observations versus current source

The current scientific numerical collection is
[results/distributed](../results/distributed/README.md). The local collection is
an archived separate experiment, not a substitute row source. The distributed
collection joins a validated ten-case prefix and seventeen-case continuation.
It does not describe one uninterrupted run. Collection manifests bind sanitized
numbers, while original seals and raw sources have a different verification scope.

Source preparation, scheduling and export tools have evolved since measurement.
A fresh execution must create its own image/source descriptor, admission evidence,
functional smoke and validation. A source hash mismatch is a reason to identify
the correct version, never to edit an old seal. No live project, registry image,
private predecessor state or original raw backup is promised by this public copy.
