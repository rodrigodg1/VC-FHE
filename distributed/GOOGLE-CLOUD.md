# Google Cloud configuration and execution

These instructions use the checked-in CLI and its generated Terraform. Run from
`VC-FHE-GITHUB/`. They describe a new experiment in a project you can provision. For an interrupted execution, use [reconciliation](OPERATIONS.md)
instead of provisioning another controller or resetting its state.

## Command effects

| Command | Effects |
| --- | --- |
| `plan`, `prepare`, `readiness` | Local planning and checks, no cloud VM creation |
| `dependencies --check` | Local prerequisite inspection |
| `dependencies --install` | Installs/downloads controller dependencies |
| `setup --login --enable-apis` | Authentication, project inspection, API enablement and local configuration update |
| `quote` | Reads cloud pricing, writes a private quote, may resolve SDK prerequisites |
| `image-prepare` | Copies and hashes build inputs locally |
| `image-build` | Local Docker build, no VM creation |
| `image-push` | Creates/uses a registry and uploads images |
| `cloud-build` | Paid temporary builder and registry operations |
| `cloud-run`, `launch` | Paid protocol hosts and real cryptographic execution |
| `cloud-results start --execute` | Paid controller and protocol execution |
| `status --run` | Reads local observations |
| `cloud-results status` | Reads cloud terminal/progress records, may use SSH |
| `cloud-results stop-compute --execute` | Stops owned compute, retains data |
| `cloud-results finish --execute` | Downloads and verifies results, then deletes verified owned infrastructure |

There is no general dry-run interpretation for `cloud-run` or `launch`.
`finish` also removes owned infrastructure after validating delivery and raw-data
preservation. New runs deliver tables, plots and observations.

The public configuration is a generic template. To target the retained measured
profile, first review [machine and zone differences](../docs/EXPERIMENTS.md#measured-deployment-and-fresh-template).
Do not assume the original project, registry images or private state still exist.
A fresh run creates its own evidence and needs source-matched preparation.

## Prerequisites and private configuration

Use the complete source package, Python 3.10 or later, Git, SSH/SCP and the
Google Cloud SDK. Terraform must satisfy the generated constraint
`>= 1.9.8, < 2.0.0`; the Google provider is pinned to `6.50.0` with a lock file.
The controller also uses Node 22.10+ within major version 22 and plotting dependencies.
Inspect them with `./run-distributed.sh dependencies --check`. A complete `VC-FHE-GITHUB/`
source directory is sufficient, including when copied without Git history.
SDK/Terraform downloads use
`.cache/gcp-preparation-tools/` inside `VC-FHE-GITHUB/`.

New preparations select public sources without including prior runs or private
state. Existing image/source/smoke checks remain mandatory. Code changes require
new matching preparations; do not rewrite historical manifests or seals.

Use a billing-enabled project with permitted Compute Engine, Artifact Registry,
IAP, Cloud Resource Manager and Service Usage operations. The authenticated
operator also needs the IAM/account operations used by the selected route.
`setup` verifies identity, billing, enabled APIs, quotas, and advertised CPU platforms.
It does not prove that every later resource or IAM write will succeed.
Confirm regional and global CPU quotas, disk quotas, addresses, IAP/OS Login
access, and actual zone capacity. A quota allowance does not reserve physical capacity.

```bash
umask 077
cp distributed/config.example.json distributed/config.local.json
# Edit only the private copy: project, campaign, regions and admitted resources.
./run-distributed.sh setup --config distributed/config.local.json \
  --enable-apis --login
./run-distributed.sh plan --config distributed/config.local.json
```

Do not overwrite an existing configuration. `setup` resolves missing supported
SDK/Terraform tools, validates billing and resource prerequisites, and records the
operator privately. It does not create evaluation VMs or change the billing account.
It cannot grant unavailable account privileges or quotas.

Terraform needs Application Default Credentials (ADC), in addition to a usable
`gcloud` login. If setup opens a new user login it requests `--update-adc`.
If an account was already active, setup does not refresh ADC. For a local user
account, configure the same identity explicitly when ADC is missing:

```bash
gcloud auth application-default login
```

Keep local credential files outside the repository. See
[Google Cloud authentication for Terraform](https://docs.cloud.google.com/docs/terraform/authentication).
The cloud controller uses its attached service account, not a copied local login.
If the wrapper downloaded tools to its private cache, subsequent bare `gcloud`
or `terraform` commands require those binaries on the calling shell's PATH.
The wrapper records the resolved executable paths in its preparation state.

Keep the schema and fixed grid fields as supplied. The full execution mode is
`evaluation`; smoke configurations are created with `smoke-config`.

| Configuration field | Meaning and constraint |
| --- | --- |
| `project_id`, `campaign` | Private project and unique experiment identity, not credentials |
| `layout` | Use `four-hosts` for the cloud-controller route |
| `regions` | Four distinct regions, matching zones and non-overlapping private /24 subnets |
| `host_machine_type`, `min_cpu_platform` | Homogeneous admitted host profile |
| `machines` | Per-role sizes for dedicated layout, unused by `four-hosts` |
| `boot_disk_gib`, `state_disk_gib` | Separate capacity planning, example 100 GiB each |
| `images` | Campaign and Besu immutable digests, never floating tags |
| `fhe_parameters`, `fhe_threads`, `kms_threads` | Test profile and pinned thread counts |
| `window_seconds` | At least 120 seconds, not an infrastructure timeout |
| `maximum_vm_runtime_seconds` | Finite VM lifetime, normally 6–24 hours |
| `budget`, quote and prior-cost fields | Estimated cumulative admission with a reserve |

N2/Intel Ice Lake is the example profile. Four homogeneous
`n2d-standard-4` hosts with `AMD Milan` are also explicitly supported. A platform
change requires new admission and matching ciphertext-byte checks. Neither an
x86-64 binary nor a successful run on another CPU establishes canonical byte
equality on the new platform. Never relax that check to obtain capacity.

## Privilege and network review before provisioning

Read the generated plan with the project administrator. The source declares
privileges for distinct actors; a successful login alone does not grant them.

| Actor | Declared access and source |
| --- | --- |
| Human/automation provisioning identity | Read project/billing/quota state, enable required APIs, create the selected resources and set their IAM bindings; organization policy can prohibit these writes |
| Protocol host service accounts | Artifact Registry reader for the campaign image, from `gcp.py` |
| Administrative access principal | OS Admin Login, IAP tunnel access and service-account use bindings, from `gcp.py` / `cloud_results/infra.py` |
| Image builder | Repository writer and scoped build-storage roles, from `cloud_setup.py` |
| Detached controller | Project compute/IAP administration, Service Usage consumer, service-account viewer, registry administration and evidence-bucket storage administration, from `cloud_results/infra.py`; controlled account-management grants are also used during start |

The detached controller has infrastructure-administration authority. Protocol
role isolation does not imply protection against that cloud administrator.
`cloud_setup.py` enumerates required APIs, including Compute, Artifact Registry,
Cloud Build, IAM, IAM Credentials, IAP, OS Login, Storage, Logging and Cloud Billing.
The chosen route can require additional controller-management APIs. Use an
appropriately governed experiment project; do not copy a broad role recipe to
unrelated infrastructure or commit the resulting IAM/account records.

Protocol hosts use private addresses on non-overlapping subnets, NAT for required
outbound access, role-scoped firewall rules, and IAP/OS Login administration. The
controller's separate network and external address have their own firewall rules.
Inspect `main.tf.json`, per-host Compose files and the private role plan before
execution. Preserve the generated firewall/IAM configuration with its run rather
than manually opening public RPC or participant ports to make a failed check pass.

## Inspect and validate the generated Terraform

The Terraform configuration is generated from JSON rather than maintained as a
separate editable `.tf` deployment. Use an unused destination:

```bash
./run-distributed.sh prepare --config distributed/config.local.json \
  --output distributed/generated/terraform-inspection
terraform -chdir=distributed/generated/terraform-inspection/terraform init \
  -backend=false -input=false -lockfile=readonly
terraform -chdir=distributed/generated/terraform-inspection/terraform validate
```

`prepare` writes `main.tf.json`, `terraform.tfvars.json`, `bootstrap.sh` and the
provider lock under `terraform/`, plus the role plan and per-host Compose files.
`init` can download the provider and writes local `.terraform/` metadata.
`validate` verifies configuration consistency without provisioning resources.
Quotas, credentials, and physical zone capacity require separate verification.
See [Terraform validation](https://developer.hashicorp.com/terraform/cli/commands/validate).

The protocol configuration in `gcp.py` declares a VPC, four subnets, regional NAT,
role-scoped firewall rules, service accounts, four VMs and separate state disks.
Protocol VMs have private addresses and use IAP/OS Login for administration.
The detached route generates a second Terraform configuration in its preparation
directory for an `e2-standard-2` controller, its network, IAM and evidence bucket.
That controller has an external address but restricts SSH ingress to IAP.
Its protocol-host configuration is generated separately during execution.

`./run-distributed.sh plan` is an offline topology summary, not `terraform plan`.
Its conservative `protocol_adapter_gaps` field describes admission of a new
source/configuration, not a live query of the retained measured campaign. Use
`results/distributed/` for historical observations and new readiness evidence for
a new deployment.
The execution wrappers perform Terraform initialization, validation, saved planning
and apply after their source/image/budget checks. The direct route imports the
already-created image registry into its new state before provisioning hosts.
Manual `terraform apply` would skip those orchestration checks and is not the
supported entry point. Edit the private JSON before preparation, not generated
files in an existing run.

Retain each Terraform state with its matching configuration, source manifest and
resource-ownership records. State disks have `prevent_destroy`; VMs have deletion
protection. Do not disable those protections or use a generic destroy command
as a recovery step. [Controller cleanup](cloud_results/README.md#shutdown-delivery-and-cleanup)
confirms ownership and preservation before removing resources and retains the
evidence bucket and image registry.

## Images: build once, verify before reuse

The cloud builder defaults to a temporary `n2-standard-8` host with a finite
four-hour lifetime. `builder_machine_type: n2-highmem-4` is the supported smaller
CPU alternative. Both retain 32 GiB RAM, Intel Ice Lake and one Cargo build job.
`builder_zone` must be one configured zone. `registry_region` may retain an
existing registry region independently of the first protocol host.

```bash
./run-distributed.sh quote --config distributed/config.local.json \
  --output distributed/quote.local.json
./run-distributed.sh cloud-build --config distributed/config.local.json \
  --quote distributed/quote.local.json --build distributed/generated/build-UNIQUE-ID
```

These commands are for new preparation. Before building, inspect an existing
build receipt and registry availability. Reuse the source-bound digest and exact
build context when valid. Do not rerun an ambiguous build or one with retained
active builder resources. A different adapter or protocol source closure needs
a separate build context and new evidence. Frozen execution sources are immutable.

`cloud-build` records both immutable image digests in the private configuration.
The native cache avoids recompiling unchanged Rust inputs. Runtime contract-cache
reuse checks sources, compiler dependencies and exact outputs. The controller
uses a separately pinned dependency environment. Keeping an image without its
matching controller is insufficient for reproduction.

A local build is an alternative, not an extra mandatory step:

```bash
./run-distributed.sh image-prepare --config distributed/config.local.json \
  --output distributed/generated/local-build-UNIQUE-ID
./run-distributed.sh image-build --build distributed/generated/local-build-UNIQUE-ID
./run-distributed.sh image-push --config distributed/config.local.json \
  --quote distributed/quote.local.json --build distributed/generated/local-build-UNIQUE-ID
```

Local building requires Docker with linux/amd64 support and sufficient capacity.
Retain the returned immutable image receipts and configure both digests before
launch. Source drift, missing images and failed preparation are blockers, not
permission to substitute a different binary.

## Functional smoke

Use a distinct private configuration and fresh state for a new smoke. A smoke
executes three complete cases: linear at 27 records and each nonlinear workload
at 50 records. It includes real four-core setup, encryption, authorization,
recipient recovery and nonlinear dispute handling. It has no measured paired
repetitions and does not replace the complete 480/18/27 design.

```bash
./run-distributed.sh smoke-config --config distributed/config.local.json \
  --output distributed/config.smoke.local.json
./run-distributed.sh plan --config distributed/config.smoke.local.json --smoke
./run-distributed.sh quote --config distributed/config.smoke.local.json --smoke \
  --hours 6 --output distributed/quote.smoke.local.json
./run-distributed.sh readiness --config distributed/config.smoke.local.json --smoke \
  --quote distributed/quote.smoke.local.json --build distributed/generated/build-UNIQUE-ID
```

The six-hour value is a planning input, not a completion guarantee. Review the
actual quote and finite VM duration. Only after preparation passes, the following
command creates resources and executes the smoke:

```bash
./run-distributed.sh cloud-run --config distributed/config.smoke.local.json --smoke \
  --quote distributed/quote.smoke.local.json --build distributed/generated/build-UNIQUE-ID \
  --run "$PWD/threshold-kms/runs/run-wan-smoke-UNIQUE-ID"
```

Smoke success must match the retained image/controller and preserved evidence.
It does not establish full-run duration, storage sufficiency, recovery after
releases or final export success. A focused diagnostic has its own reduced scope
and cannot silently replace an omitted functional check.

For a local transport-only check, use `docker-check --output NEW_DIRECTORY`.
It starts isolated test containers and verifies TLS, chunks, permissions and
request deduplication. It performs no native KMS setup or encrypted workflows.
Its temporary resources are separate from retained protocol state.

## Full execution and cost admission

Prefer the [cloud-controller route](cloud_results/README.md) when the local
computer cannot hold raw evidence. The direct `launch`/`cloud-run` route uses
its executing host for collection and requires at least 50 GiB free on the
run-evidence and temporary-archive filesystems, checked once if shared.
This is a minimum guard, not a bound on total storage growth.

The default quote uses 14 hours, traffic/storage allowances and a reserve.
Current prices and cumulative prior costs must be included. Quotes expire and
stale network-rate assumptions are refused. The example's US$50 budget is an
admission estimate, not a billing cap or demonstrated total execution cost.
The cloud-controller completion profile has separate explicit authorization and
finite-duration rules, described in its guide. Never erase prior costs, shorten
protocol windows or reduce the fixed measurement grid to pass admission.

Every launch needs unique empty execution paths. An existing start intent,
active service, ambiguous launch acknowledgement or consumed lineage must be
reconciled before any further action. `primary_first_provision: true` can limit
initial capacity failure to the first host, but all four hosts must be ready
before protocol work begins. It is not a partial-topology execution mode.

Account for setup, encryption, measurements, validation, backup and shutdown
separately. Preserve time for a complete next case before admission. Read-only
transport retries are different from replaying a transaction or release.
Stopping compute leaves storage charges. Verify actual shutdown and later
owned-resource removal using [the storage guide](STORAGE.md).
