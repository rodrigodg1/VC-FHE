# Storage, privacy and shutdown verification

## Separate data by purpose

| Material | Store | Handling |
| --- | --- | --- |
| Generic instructions, example schemas, tests | Public repository | No real accounts, resources or secret values |
| Configuration, quotes, Terraform state, VM/object identities | Ignored private control directory | Restricted permissions, retained provenance |
| KMS shares, signing keys, owner jobs, chain and quota state | Original private host disks and restricted backups | Never public, never disposable cache |
| Raw ciphertexts, measured binaries, complete logs | Private cloud evidence storage | Preserve original bytes and execution bindings |
| Checkpoints and raw validation receipts | Private cloud objects and small local copies | Exact generation, checksum and full readback |
| CSVs, tables, plots, sanitized reports | Bounded local result delivery | Verify manifest and review metadata before sharing |
| Immutable images and matching controller/build sources | Registry and private source checkpoint | Preserve digest, locks, transforms and source inventory |

Restrictive file permissions and private bucket access do not mean an exported
TAR is encrypted as a file. Existing private TARs contain sensitive participant
state. Treat them accordingly when changing storage destinations. A public
certificate is not a private key, but its associated resource metadata may still
identify an experiment.

## Capacity before paid work

The full collector requires at least 50 GiB free on each distinct evidence and
temporary-TAR filesystem. On the detached route that check runs in the cloud.
It does not account for every possible dataset, archive or readback size.

Plan separately for live protocol data, archive staging, a complete readback,
logs, source copies, retained predecessors, snapshots and final delivery. Archive
scratch must be outside the source being archived. Do not accidentally archive
an archive into itself. Check regional disk quota before expansion. Never format
a disk that contains existing chain, keys or counters.

The workflows-only continuation uses explicit margins including 16 GiB for
additional participant data and space for archive/readback. Alert below 16 GiB
free on a participant. The local result TAR is capped at 256 MiB, but extraction,
source copies and retained predecessors need additional space. Local disk
exhaustion can prevent control records and delivery even while cloud work continues.

The storage planning period is not automatic evidence expiration. Stopped VMs
still have billable disks, snapshots, objects and images. Deletion must be an
explicit separate decision after preservation is verified.

## Cloud object verification

For each backup retain: logical scope, source inventory, creation time, byte
length, SHA-256, provider checksum, object generation and complete readback result.
Keep real bucket/object references in private receipts only.

1. Quiesce the relevant writer before archiving a consistent state.
2. Create a new destination with create-only semantics. Never overwrite evidence.
3. Read the exact uploaded generation back completely, within a finite timeout.
4. Check archive hash, member paths, per-file hashes, source identity and inventory.
5. Retain the original receipt and separate failure or verification outcome.

A metadata lookup, successful upload acknowledgement or matching object size is
not complete readback. A checksum mismatch is a failure. If readback times out,
inspect the live worker, local scratch and exact remote generation. Do not rerun
the upload, collection or workflow against existing destinations automatically.

For a verified object, retrieve its recorded generation to a private directory
with sufficient capacity. This example performs a download, not restoration:

```bash
umask 077
gcloud storage cp 'gs://BUCKET/runs/RUN_ID/host-1/private-state.tar#GENERATION' \
  ./host-1-private-state.tar
```

Verify its SHA-256 against the independent retained receipt before extraction.
Inspect paths and reject traversal/symlinks as required by the original extractor.
Retrieval alone does not authorize replaying the protocol.

## Snapshots and restoration

Record each disk's exact provider identity, attachment, logical role and snapshot
identity privately. Confirm snapshot `READY` and matching `sourceDiskId`. Include
all state-bearing disks, not only boot disks. Preserve configuration, images,
controller sources and restore instructions alongside the data.

A completed snapshot preserves disk state at a point in time. It does not prove
per-file integrity or application-consistent recovery. Record whether writers
were quiesced and whether a restore was tested. Do not label a snapshot receipt
as successful TAR readback. An interrupted archive may coexist with valid snapshots.

Restore into an isolated inspection context first. Verify keys, chain identity,
policy lineage, counters, ciphertext hashes and completed requests before any
continuation. Do not initialize a restored disk as though it were a fresh run.
Retain the matching source descriptor and restore procedure with the backup.

## Private Drive copies

For numerical reproduction retain the checked collection under `results/`.
Keep full raw-state backups separate and private. Numerical exports alone cannot
revalidate cryptographic execution or restore a consumed release-policy lineage.

Identify the package format from its own manifest before retrieval:

- Split gzip/TAR packages have ordered byte-range parts. Check every part's size
  and SHA-256, concatenate in manifest order, then inspect the resulting archive.
  Individual parts are not independently extractable archives.
- Content-addressed ZIP packages contain `objects/<sha256>`, source references
  and a source binding. A reference may point to an object in an earlier package.
  Resolve the complete verified index; one ZIP is not necessarily a self-contained
  host backup. A SQLite checkpoint may also list prepared, unverified batches.
  Only receipts proving completed verification establish a retained copy.

For either format, compare the downloaded package with the retained receipt,
check archive decoding/CRC and each original member hash, and reconcile all
required paths with the source inventory. CRC checks alone do not establish
identity with the source. Restore only the needed files into a new private
directory after checking free space. Reject absolute paths and traversal, and
do not follow archived symlinks while writing files. Preserve the originals and
the source-to-object mapping. Do not unpack an entire heavy archive onto a
space-constrained computer merely to read a small metric file.

Source snapshots with the same disk ID can represent different states. Backup
coverage must identify the snapshot/version and exact paths, not only the host.
An inventory contains metadata, not the referenced bytes. Resource deletion
requires reconciliation of every unique required result against verified local
or private-backup contents, together with the local delivery requirement.
Numerical usability, a completed upload or a successful snapshot status is not
that deletion decision.

Long-lived OAuth credentials, refresh credentials, access tokens and resumable
upload URLs must never enter a backup package or a public repository. A temporary
transfer VM should receive only the credential needed for its finite window,
with restricted permissions. Reconcile an interrupted transfer against its
recorded file/session identity before retrying; do not blindly overwrite or
duplicate evidence. Keep temporary compute bounded and confirm its actual stop.

## Confirm actual compute shutdown

A stop request or local stop log is insufficient. Query the provider for every
owned VM after preservation workers have been reconciled. Keep output private:

```bash
gcloud compute instances describe VM_NAME --project PROJECT_ID --zone ZONE \
  --format='json(id,name,zone,status,lastStopTimestamp)'
gcloud compute instances list --project PROJECT_ID \
  --format='json(id,name,zone,status)'
```

Compare exact IDs and zones with ownership receipts and cross-check the project
inventory. Require `TERMINATED` for retained VMs. `STOPPING`, missing permission
or an SSH refusal does not prove shutdown. A missing VM is a distinct result and
requires identity/absence evidence. Inspect unexpected active experiment resources
without stopping unrelated instances. Check temporary builders as well as the
protocol/controller hosts. Record the verification timestamp and outcomes.

Do not run a blanket project shutdown. Use the matching controller's scoped
stop procedure or an individually reconciled action. Removing resources requires
verified preservation, required local delivery and an identity-checked deletion
plan. Retain original Terraform state and cleanup journals. Never destroy disks
just because compute is stopped.

## Public-data hygiene

Use `*.local.json` and ignored control directories for real values. Restrict new
private directories and files with `umask 077`. Git-ignore is not access control.
Do not commit Terraform state/plans, SDK credential folders, private PEMs, service
account keys, tokens, raw cloud logs, participant vaults or private archive URLs.
Do not paste these into issue reports or screenshots.

```bash
./run-distributed.sh audit-public
git check-ignore distributed/config.local.json
git status --short
```

`audit-public` checks repository-eligible files for configured sensitive patterns
and disallowed private file types. It does not read ignored credentials or prove
the absence of all sensitive information. Review filenames, addresses, resource
identifiers and free-text logs manually before sharing. Publish only sanitized
failure causes and generic reproduction steps. Keep filled state references private.
