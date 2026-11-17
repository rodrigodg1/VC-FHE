# Detached cloud controller and bounded result delivery

This route runs the complete 480-pair, 18-warm-up, 27-workflow design using four
geographic protocol hosts and a fifth administrative VM. The administrative VM
runs orchestration, original evidence validation and derived reporting beside
the large data. It contributes no validator, KMS share or measured participant
work. Its service runs under systemd independently of the local SSH connection.

The controller uses two vCPUs, 8 GiB RAM and a 200-GiB disk in the first configured
region. The full evidence-space guard requires 50 GiB free on the controller.
That guard is not a forecast of total storage use. See [storage](../STORAGE.md).

The complete source directory can be copied independently. `finish` downloads
and verifies numerical results before guarded teardown.

## Preconditions

Complete [project, credentials, Terraform and image preparation](../GOOGLE-CLOUD.md)
first. `cloud-results prepare` is separate from the offline topology-only
`prepare` command. Its configuration needs an authenticated operator and
source-matched image/smoke evidence. The local shell also needs the controller
dependencies; `cloud-results` does not run the full prerequisite installer.

- A private full configuration, four-host topology and current cumulative quote.
- An available immutable campaign/Besu image pair and matching build receipt.
- A source-matched successful functional smoke, including preservation and
  cleanup evidence. A specifically validated postcollection attestation retains
  its original failed records and cannot be treated as an ordinary passing seal.
- Sufficient CPU/disk/address quotas, controller permissions and storage headroom.
- A new preparation directory for a new execution, with no previous start intent.

Restore the matching retained source checkpoint for an older execution. Inspection with a later checkout can fail source guards. That refusal
must not be bypassed by rewriting a manifest or preparing the same execution again.

## Prepare locally

Commands run from `VC-FHE-GITHUB/`. Substitute paths and the actual prior-cost estimate.
Preparation does not start a smoke or a full execution.

```bash
./run-distributed.sh cloud-results quote \
  --config distributed/config.local.json \
  --prior-usd ESTIMATED_PRIOR_COST \
  --output distributed/generated/full-quote.local.json
./run-distributed.sh cloud-results prepare \
  --config distributed/config.local.json \
  --quote distributed/generated/full-quote.local.json \
  --build distributed/generated/VERIFIED_BUILD_CONTEXT \
  --output distributed/generated/NEW_FULL_PREPARATION
./run-distributed.sh cloud-results check \
  --prepared distributed/generated/NEW_FULL_PREPARATION
```

`quote` reads current catalog prices, including the controller, retained disks,
storage, registry, transfer allowances and prior costs. `prepare` runs the offline
regression gate, freezes configuration/source/build evidence and verifies a public
source cache before reuse. `check` verifies the prepared snapshot and admission.
Neither preparation nor a successful check proves runtime completion.

The ordinary budget admits an explicitly configured ceiling up to US$100, with
US$50 in the example. The separate `completion_authorization` profile requires an
explicit owner decision to complete beyond the former reference budget. It keeps
prior costs and reserve visible and has a US$125 estimated admission envelope.
These are forecasts, not billing caps. The completion profile permits up to 24
hours for protocol hosts and two additional hours for controller work. Protocol
windows and quorum checks do not change. Review `completion_budget.py` before
using that profile. Do not erase cost history or remove finite runtime guards.

## Start once and observe

This command creates paid resources and begins a new execution:

```bash
./run-distributed.sh cloud-results start \
  --prepared distributed/generated/NEW_FULL_PREPARATION --execute
```

`start` validates source hashes, image availability, identity, capacity, and budget.
It enables missing controller-management APIs, allocates fresh empty host accounts
and transfers the frozen bundle. VM metadata identities supply cloud access.
No downloadable service-account key or local login cache is copied to the VM.
Public KMS certificates are transferred with readable permissions while private
keys retain restricted permissions. Dependency installations reuse verified locks.

A durable `start-intent.local.json` precedes launch. A second start is refused.
An SSH timeout or missing acknowledgement does not prove the service failed.
Reconcile its live state before considering recovery.

```bash
./run-distributed.sh cloud-results status \
  --prepared distributed/generated/NEW_FULL_PREPARATION
```

`status` first looks for terminal cloud records and otherwise reads progress
through SSH. It never intentionally repeats a protocol operation. Confirm the
provider state before attempting SSH to a stopped controller. If the observer fails, report
observation unavailable rather than reusing an old count as current. See
[operations](../OPERATIONS.md) for full-case counts and incomplete requests.

## Validation and preservation

The unchanged native validators require public owner witnesses, recipient-output
checks, authorization receipts, exact counters, source bindings and the complete
grid. The collector retrieves only admitted public owner material, not entire
owner directories containing plaintext/private jobs. Collection does not repeat
computation, approval or release.

For an uninterrupted execution the original validation and seal remain required.
For a reconciled continuation, validate each segment under its own bindings and
then validate the composed case grid and cumulative release history. A 17-case
segment is not a complete 27-case run. The completed-prefix procedure and offline
evidence adapter are separate from this original single-run controller.

Cloud backups use create-only objects, exact generations, checksums and complete
readback. The local transfer limit is 256 MiB for the result archive, not for all
extraction, source preparation and backups combined. Large ciphertexts, binaries,
chain databases and private KMS state stay in restricted cloud storage. Public
status records must not include object locations or private cloud identifiers.

A terminal application success is distinct from successful backup and delivery.
An archive/readback timeout retains its failure even if workflows all passed.
Reconcile the worker and object generation before any retry or shutdown. Never
repeat an export into an existing create-only destination. Retained disk snapshots
are a separate preservation mechanism, not a substitute file-readback receipt.

## Shutdown, delivery and cleanup

After work and preservation have been reconciled, compute can be stopped without
deleting retained data:

```bash
./run-distributed.sh cloud-results stop-compute \
  --prepared distributed/generated/NEW_FULL_PREPARATION --execute
```

This command is a mutation. Do not run it while a required backup is actively
writing without inspecting that worker. It records stop outcomes and checks
provider state. Independently confirm exact VM IDs and `TERMINATED` as described
in [storage and shutdown](../STORAGE.md). A status file alone is insufficient.

After a new full run completes:

```bash
./run-distributed.sh cloud-results finish \
  --prepared distributed/generated/NEW_FULL_PREPARATION --execute
```

This requires the matching preparation, a successful terminal report, verified
cloud backups and a complete local copy. It delivers `results/composite/` with
observations, CSV/Markdown tables, PDF/PNG/SVG plots and hash inventories.
`results/proof/` retains cloud validation and preservation receipts. The package uses the `cloud-results-delivery-v1` format.

`finish` then removes verified owned infrastructure. It is not download-only.
It must not be used for a segmented run lacking its separate composed-validation
and delivery record. Missing files or altered plots block teardown. 

Teardown verifies live identities and validates a deletion-only plan using a
disposable copy of Terraform state. Original state is preserved. The controller is removed last.
The evidence bucket and registry are retained. Failed delivery, changed
sources, ambiguous ownership or incomplete preservation block teardown. Inspect
journals after interruption rather than regenerating a destructive plan blindly.

## Offline checks

```bash
./run-distributed.sh test
```

The wrapper runs adapter Python tests, both recovery suites and Node tests without
starting cloud resources. Coverage includes source drift, duplicate operations,
create-only storage, unsafe archives, capacity guards and scoped cleanup. Test
success does not certify a particular cloud execution. Validation scope is recorded in [the check report](../../docs/VALIDATION.md).
