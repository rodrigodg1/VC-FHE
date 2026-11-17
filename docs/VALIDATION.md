# Distribution validation

## Documentation and offline verification — 2026-11-07

The [review report](DOCUMENTATION-REVIEW.md) and [machine-readable record](documentation-review.json)
record the current review. **909 regression tests passed**, including 29 bounty
contract cases, 27 lowering tests and 75 toolkit cases. Both numerical collections
passed hash/count/statistic reconciliation; three distributed figures were
regenerated with their numerical values. Six commands also passed in a disposable
copy without Git history, sibling source trees, cached dependencies or private runs.

The retained 70-theorem proof report matches the current proof/checker hashes and
19 mapped source files. The original formal verification records remain unchanged.
The pinned commands for independent kernel verification are in
[formal/README.md](../formal/README.md). The historical checks below retain their
original date and scope.

## Distribution checks — 2026-11-01

Checked on 2026-11-01. These checks cover source preparation, orchestration regressions and numerical
reproduction.

## Executed checks

| Check | Result |
| --- | --- |
| Campaign Python tests | 198 passed |
| Postprocessing Python tests | 37 passed |
| Local profile-specific recovery tests | 41 passed |
| Distributed adapter/controller Python tests | 397 passed |
| Zero-release cloud recovery tests | 22 passed |
| Completed-prefix cloud recovery tests | 25 passed |
| Distributed Node tests | 42 passed |
| Total | 762 passed |
| Python, Bash and JavaScript syntax | Passed |
| Root Docker Compose configuration | Parsed successfully without starting services |
| Generated Terraform | Initialized with the locked Google provider; `validate` passed |
| Public numerical collections | Both passed hashes, counts and statistical reconciliation |
| Plot generation | All three figures generated for each collection, with CSV/JSON values |
| Current cloud numerical renderer | Exercised with retained numeric inputs in a disposable fixture |
| Public source audit | Passed configured private-state/path checks and required build-input inventory |
| Retained cloud plots | 35 copied files match their originals byte for byte; all 54 supplementary plot rows match the grouped metrics |
| Cloud result privacy checks | Text and decompressed JSON inspected; account/transaction labels checked; PNG and PDF metadata inspected |

The economic detail export replaces 144 account references, including dictionary
keys, with the same opaque labels used by the receipt partition. All 18 economic
rows retain their financial quantities. The diagnostic summary retains its
statistics and review status.

The numerical checks cover 1,504 grouped metrics per collection, from 11,266 local
and 8,392 distributed observations. The distributed CPU and decision analyses
also reconcile their process records and receipt endpoints. No missing value was
filled and no observation was replaced by a new measurement.

The check environment used Python 3.14 and Node 22.20.0. Plotting used the pinned
Matplotlib 3.10.8 environment. JavaScript tests used the dependency installations available for that record.

## Independent-directory check

A disposable source copy outside the development workspace, without Git history,
was used to execute launcher help/design commands, distributed topology planning,
Terraform generation, public-source selection and numerical reproduction. These
commands did not read a sibling project or create cloud resources.

The public-distribution audit rejected a disposable copy after a generated
runtime directory was added. The clean source distribution passes that audit.

## External requirements and component scope

- Execution uses the source-matched build and readiness commands in the local
  and cloud guides. External toolchains, datasets, credentials, quotas and capacity
  are explicit prerequisites.
- Local recovery of the default bounty-v2 profile remains unvalidated. Earlier
  recovery tools retain their narrower scope.
- The retained `examples/linear-applications/` package lacks its inherited shared
  `lib/scenario.mjs`. Its demo/test commands are not runnable in this snapshot.
  This optional source example is not used by the supported linear campaign.
- Retained numerical observations support data analysis, not restoration of keys,
  policy state or complete raw cryptographic revalidation.

Use [development checks](DEVELOPMENT.md), [local reproduction](../REPRODUCE.md) and
[the cloud runbook](../distributed/GOOGLE-CLOUD.md) for their separate scopes.
