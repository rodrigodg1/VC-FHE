# Public documentation review — 2026-11-07

The review compared this public source tree, its numerical collections, the
current specification and the added protocol/incentive models. It changed no
protocol implementation, measured data, original proof source or execution seal.
The machine-readable [verification record](documentation-review.json) separates
checks executed now from retained historical evidence.

## Coverage and changes

| Area | Documentation and evidence |
| --- | --- |
| Roles and architecture | Expanded [architecture](ARCHITECTURE.md), component map and role/interaction diagram |
| Protocol execution | New [protocol guide](PROTOCOLS.md): linear delivery, canonical trace/audit/dispute branches, operation guards, exact authorization and KMS request checks |
| Incentives and proofs | New [incentives guide](INCENTIVES.md): strategies, funding, all settlement branches, payoff derivations, sufficient deterrence, participation, worked calibration, source/theorem links and limitations |
| Guarantees | New [evidence map](EVIDENCE.md): conditional claims, formal interfaces, implementation tests and observations |
| Local and cloud reproduction | Entry-point instructions retained and cross-checked; added measured/template differences, state boundaries, IAM/network responsibilities and interpretation of readiness |
| Experimental design | New [experiment guide](EXPERIMENTS.md): pinned inputs, encoding, baselines, counts, orders, 45-case local versus 27-case geographic design |
| Data use | New [data dictionary](../results/DATA-DICTIONARY.md): fields, exact integers, joins, missingness, timing/CPU/gas scopes, and integrity-versus-raw-validation boundary |
| Navigation | Root/component indexes linked to the new guides; `scripts/check-docs.py` checks relative links and Markdown heading anchors |

## Inconsistencies corrected or delimited

1. The old game-theory plotting script includes mirror/diligence compensation.
   The documentation now identifies it as a legacy model, rather than evidence
   for bounty-v2, whose agreement reward and secondary-report correctness penalty
   are absent. The historical script is retained unchanged.
2. Positive payoff after detecting a fault was insufficiently distinguished from
   profitable ex-ante replay. Both inequalities, their probability inputs and the
   absence of a guaranteed honest auditor are now explicit.
3. The deployment template selects Intel N2 and some different zones; retained
   observations used AMD N2D. The guides now point to the measured setup and
   explain how a new private configuration can target it without claiming
   equivalent timing or byte-repeatability in advance.
4. A numerical manifest and an original execution seal establish different
   scopes. The guides now state that curated observations do not restore raw
   ciphertexts, private keys or every historical host journal. They cannot prove
   complete original cloud-file preservation.
5. Recipient verification duties in the specification and the PoC's delegation
   to owners/coordinator are distinguished. A coordinator check is not described
   as independent recipient verification.
6. `toolkit/` has no dependency lockfile, so its former `npm ci` instruction was
   removed. Its test suite had an obsolete 14-opcode expectation. The test now
   checks all 15 existing numbered entries, including `ADD_CHAIN=15`; execution
   code was not changed. All 75 tests pass.
7. Component aliases pointing to absent optional examples and the missing
   `examples/linear-applications/lib/scenario.mjs` are identified at their entry
   pages. Supported campaign routes do not depend on them.
8. Preparation metadata can conservatively describe an unvalidated new source
   version. That is not a live status query or a denial of retained measurements.
   Historical resources and images are not promised to remain accessible.

9. The public distribution inventory predated the formal package. It now includes
   the 70-result package and reviewed documentation, with current file hashes.
   Original numerical manifests and formal source-correspondence hashes were
   preserved.

## Checks actually executed

- 198 campaign, 37 postprocess and 41 local recovery Python tests.
- 397 distributed Python tests, 22 zero-release and 25 completed-prefix recovery
  tests, and 42 distributed Node tests through the supported offline gate.
- 27 lowering, three budget-calibration, 29 isolated bounty-contract, 13 linear
  contract and 75 toolkit tests. Total across the suites: **909 passed**.
  The linear tests used the local Hardhat EVM and its Solidity compiler cache;
  they are component checks, not a new grouped-radix threshold campaign.
- Locked JavaScript dependencies installed using the available npm cache. Initial
  missing-dependency failures disappeared after installation. A sandbox initially
  blocked loopback TLS tests; they passed with local socket access. No cloud
  resources were created by these tests.
- Both public numerical collections passed manifest hashes, grouping/counts,
  means, sample standard deviations and range reconciliation. Distributed checks
  also reconcile decision endpoints and process CPU. Three figures were generated
  in PDF/PNG/SVG with CSV/JSON values into a new ignored derived directory.
- A disposable source copy without Git history, dependencies, private runs or a
  sibling implementation passed launcher help/list, cloud topology planning,
  both numerical collections, public-source audit and documentation link checks.
- All 70 retained theorem-source hashes, the checker, source manifest and 19
  mapped implementation files matched the existing formal verification record.
  No protocol source hash was replaced to obtain a pass.
- Relative documentation links and anchors passed `python3 scripts/check-docs.py`.
  Configured public-data/path checks passed `python3 scripts/check-public.py`.
  These checks do not prove the absence of every sensitive field or validate
  external website availability. The final working-tree audit identified an
  absolute host path in the ignored Hardhat compiler cache created by the linear
  test. The clean release copy excludes that cache and passes. The cache is not
  included in the distribution inventory; no detector was weakened.

## External requirements and component scope

The repository includes the local and distributed launchers, source-bound native
build scripts, Docker/Compose configuration, Terraform generator and provider
lock, pinned dataset acquisition, measurement collectors, validators and numerical
generators. The entry points and their supporting files are listed in
[reproduction targets](EXPERIMENTS.md) and [architecture](ARCHITECTURE.md).

Execution requires the documented external tools, permitted input access and
adequate host resources. Cloud execution additionally requires a configured
project, credentials, permissions and quotas. These dependencies are explicit in
the [local guide](../REPRODUCE.md) and [cloud guide](../distributed/GOOGLE-CLOUD.md).

The formal package retains 70 kernel-checked results and seven rejection-control
records. Their source identities were checked against the delivered package.
Independent verification uses Lean 4.19.0 and the commands in
[formal/](../formal/README.md). The model-to-code mapping is reviewed; the theorems
prove statements about the models under their declared premises.

Local bounty-v2 recovery and cloud continuation tools have the profile/frontier
scope documented at their entry points. Optional incomplete examples remain
inspection-only. The supported complete experiment commands are identified
separately from those examples.

Independent readers can follow the source and proof maps, reproduce the numerical
analysis and use the documented scripts to prepare and execute local or cloud
experiments. Preservation and validation steps remain part of those procedures.
