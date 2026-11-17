# Observation and recovery

Use the exact controller and source checkpoint associated with an execution.
Do not repair a live source tree in place. New infrastructure fixes belong to a
new, versioned preparation after diagnosis, preserving old records and outcomes.

## Read progress without changing execution

For a direct-launch run, read its local controller snapshot:

```bash
./run-distributed.sh status --run "$PWD/threshold-kms/runs/RUN_ID"
```

For the detached cloud route use `cloud-results status --prepared PREPARED`.
It reads cloud records and may read the controller by SSH. Neither command is a
resume command. Verify whether the VM exists and is running before using SSH.
Check the matching local terminal, failure, preservation and stop receipts first.

Report the observation timestamp, segment and phase with these separate counts:

| Count | Required interpretation |
| --- | --- |
| Prepared/restored owners | Input or state readiness, not completed comparisons |
| Measured pairs / 480 | Verified comparison observations, excludes warm-ups |
| Warm-ups / 18 | Separate unmeasured preparation observations |
| Full workflows / 27 | Distinct `full-case done` events matched to the plan and evidence |
| Preserved checkpoints | Object/checksum/readback status, not protocol completion |

A start intent, service start, application row or isolated release does not prove
a complete workflow. For a continuation, add only the independently validated
completed prefix to new distinct full-case completions. Reject duplicates,
reordered or foreign case IDs and mismatched segment bindings.

During a healthy run inspect metrics, transport logs, CPU/resource samples,
checkpoint timestamps and remaining storage. Missing initial application reports
can be expected before inputs are ready. Samplers normally stop after completion.
Do not misclassify that terminal stop as a participant crash.

More than 45 minutes without a fresh observation during an active phase warrants
an observation alert, not a declaration of deadlock. Compare controller service,
VM state, progress-log times and current case evidence. An SSH/network error can
interrupt the observer while the detached service continues.

## Decide before taking action

| Observed condition | Next action | Do not do |
| --- | --- | --- |
| Fresh progress and healthy participants | Continue read-only observation | Restart or rebuild |
| Observer transport failure | Inspect provider/service state, retry reads within bounds | Start another controller |
| Source or digest mismatch | Restore the matching frozen checkpoint for inspection | Edit expected hashes |
| Failed provisioning before participant setup | Inspect exact ownership, use restricted cleanup if applicable | Treat initialized disks as disposable |
| Comparisons complete, no release/consumed slot | Reconcile and evaluate zero-release recovery | Assume the absence of a local result proves no release |
| Some workflows completed | Reconcile a completed prefix and every pending request | Use zero-release recovery |
| Release completed but workflow incomplete | Reconcile that individual request, slot, result and settlement | Resubmit or invent a completed case |
| All workflows complete, export failed | Preserve disks, reconcile archive worker/object/readback | Recompute workflows |
| Insufficient storage | Preserve data, inspect usage and approved capacity options | Delete raw evidence or format a retained disk |

## Recovery invariants

Before any continuation, preserve source and image hashes, original failures,
configuration, full logs, recipient requests/results, receipts, policy counters,
blockchain data, keys, ciphertexts and accumulated costs. Take verified backups
or source-identity-bound snapshots as appropriate. Keep compute stopped during
offline development when no live execution or required export is using it.

Reconciliation must inspect the original fixed-block validator evidence and
current canonical state, completed transactions, consumed slots, reservations,
request keys, owner quota deltas and recipient outputs. Account for historical
unused consents explicitly. Lack of a success message is not evidence of no effect.

Preserve the same keyset, identities, chain, policy lineage, encrypted inputs and
spent quotas. Select only proven pending cases. Use an empty continuation exchange
so the recipient cannot rediscover old completed requests. Retain all-owner consent
and exact recipient-bound approval for new requests. No completed comparison,
warm-up, transaction, workflow or release may be replayed.

A new finite infrastructure window can address administrative exhaustion only
after reconciliation and versioned preparation. Keep original time/cost origins,
per-case allowance and VM limits. Do not change contract deadlines, quorums, FHE
operations or validation criteria. A security/correctness failure cannot become
success by weakening an assertion.

## Available procedures and limits

- [Provisioning cleanup and observation maintenance](maintenance/README.md) has
  narrow ownership and stage requirements. It is not general repair automation.
- [Zero-release continuation](maintenance/workflow-recovery/README.md) requires
  the completed 480/18 comparison phase with no completed full workflow, release
  or consumed slot.
- [Completed-prefix continuation](maintenance/completed-prefix-recovery/README.md)
  was developed for the reconciled ten-case prefix and seventeen pending cases.
  Its historical success does not authorize arbitrary prefix recovery.

These procedures require private source and state checkpoints. Private launch
helpers from an old execution are not generic runbooks. Keep original failed
states and separately validated segments. The ordinary single-run exporter does
not accept a segmented campaign without its separate composed validation.

## Verify closure

Validate each segment independently, then exact coverage and release/counter
continuity. Preserve original failed statuses alongside valid completed-prefix
evidence. Keep raw originals separate from derived tables and observation mirrors.
After preservation and required local delivery, confirm all owned compute stopped
through current provider reads. Storage retention and deletion are separate
operations with separate evidence and authorization.
