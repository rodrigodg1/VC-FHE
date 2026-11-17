# Recovery scope

**Recovery of the default bounty-v2 local campaign is not yet validated.**
Preserve an interrupted run and inspect it before any continuation. Do not invoke
an older recovery tool on it, replay a release or launch the full campaign as if
that were a resume.

Retain configuration, sources, logs, reports, binaries, fixtures, KMS vaults,
policy state and chain volumes. Determine which requests were reserved, released
and settled. A correctness or authorization failure is not an infrastructure
interruption and cannot be turned into a passing seal.

`recover_v3.py` handles its earlier V3 profile after supported infrastructure
interruptions. It refuses completed runs and correctness/security/code failures.
It preserves a settled prefix and validates exact coverage, reservations and
counter deltas. `recover.py` belongs to the earlier file-ledger profile. Their
scope does not establish support for bounty-v2 deployment or payment obligations.

`readiness_prefix.py`, `nonlinear_readiness_prefix.py` and
`dispute_readiness_prefix.py` audit narrowly defined completed readiness prefixes.
They do not authorize arbitrary recovery. Source drift and an unrecognized
failure must stop inspection rather than broaden these tools' scope.

A completed sealed run can resume analysis using `--postprocess-only`. That
operation executes no transaction. Initial setup resumes only its own recorded
provisioning checkpoints with the same identities and Docker state. Cloud
continuations have [separate scope and procedures](../../distributed/OPERATIONS.md).
