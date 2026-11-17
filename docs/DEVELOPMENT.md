# Development and checks

Use Node 22.10+ within major version 22 and Python 3.10+. Dependency installation
is distinct from launching a campaign. From the repository root:

```bash
npm --prefix fhe-pod ci
npm --prefix BN254-Signatures ci
python3 -B -m unittest discover -s threshold-kms/campaign
python3 -B -m unittest discover -s threshold-kms/postprocess
./run-distributed.sh test
python3 results/reproduce.py
python3 scripts/check-public.py
python3 scripts/check-docs.py
```

The cloud command runs Python adapter tests, two separate recovery suites and
Node tests. It does not create resources. Tests use synthetic data and mocked
provider operations where indicated. Passing them does not establish full
FHE/KMS or cloud execution on the current source version.

`check-docs.py` validates relative Markdown targets and heading anchors offline.
External URLs and fenced examples require separate review. `check-public.py`
scans for configured patterns. Use both tools alongside manual review. Run the
public audit on a clean release copy. Hardhat compiler
caches contain absolute host paths even when Git ignores them; the audit correctly
rejects a working tree containing those paths. Exclude generated/cache directories
when packaging, then audit the actual release copy. Do not archive the working
directory wholesale or change the detector to accept personal paths.

Shells must expose Node/npm on PATH before Python tests that invoke
Node. Install the locked `fhe-pod` dependencies before those tests. Some offline
cloud tests bind temporary loopback TLS sockets, which restrictive sandboxes can
block even though no cloud operation occurs.

## Component tests

```bash
npm --prefix toolkit test
node --test fhe-pod/contracts/test/bounty-economics.test.mjs
npm --prefix fhe-pod run test:canonical-bounty
npm --prefix fhe-pod run test:lowering
npm --prefix BN254-Signatures run test:mklhs
cargo test --release --manifest-path output-binding-lhs/Cargo.toml
```

Contract suites that require a live chain must use their documented chain
harness and network settings. Do not point tests at a chain with retained release
budgets. Native FHE tests can be slow. The package scripts list further explicit
contract, authorization, adversarial and canonical-execution tests.

## Source and result changes

The build records source hashes, upstream revision, locked dependencies, binaries
and the image digest. A modified source tree needs a new build context and smoke.
An old matching image is not assumed valid after a change. Keep measured sources
and result seals immutable. Do not change expected hashes to bypass a failed
runtime or evidence check.

Analysis changes do not require replaying releases. Derive into a new directory,
validate the original source evidence and compare the resulting numeric outputs.
When changing timer boundaries or protocol execution, collect matching new data.

The [validation report](VALIDATION.md) records the tests and verification steps
performed for this distribution and the dependencies of each reproduction route.

## Formal verification

Install the toolchain pinned by `formal/lean-toolchain` (Lean 4.19.0), then:

```bash
cd formal
python3 check.py
python3 test_verifier.py
lake build
```

These commands verify the protocol models, source correspondence hashes and
rejection controls. They run no FHE, blockchain or KMS service. See
[formal scope](../formal/README.md) and [economic derivations](INCENTIVES.md).
Do not replace a source-manifest hash just to make a changed contract pass the
audit. Review its correspondence and retain new verification evidence separately.

## Dependency and execution boundaries

| Tool or input | Pin / source of truth | Used for |
| --- | --- | --- |
| Python 3.10+ | Controller syntax and tests | Planning, validators, numerical validation |
| Node 22.10+ within major 22 | Component `package.json` and npm locks | Contracts, transport and offline tests |
| Rust / TFHE / KMS | Campaign build scripts, upstream commit and Cargo locks | Native execution; separate component profiles retain separate locks |
| Besu 25.3.0 locally | `network/validators-besu/docker-compose.besu.yml` | Four-validator QBFT, chain ID 46853, two-second blocks |
| Docker and Compose v2 | Launcher prerequisite checks | Local campaign services and native build |
| Matplotlib 3.10.8 | `threshold-kms/postprocess/requirements.txt` | Numerical plots, not required for checksum-only replay |
| Lean 4.19.0 | `formal/lean-toolchain` | Model/component proof verification with bundled Std |
| Terraform and Google provider | Generated constraints and `distributed/terraform.lock.hcl` | New cloud provisioning, not numerical replay |

`npm ci` requires the relevant package lock. The dependency-free `toolkit/` has no
lockfile and uses `npm test` directly. Component tests on an in-process EVM are
not measurements on Besu. Keep `VCFHE_TEST_RPC_URL` unset for isolated bounty tests;
an explicitly set URL changes the target and can submit transactions there.

## Public distribution inventory

`source-inventory.json` binds the files in this public release, including the
formal package and technical documentation. It is a distribution checksum list,
not a measurement seal or the formal model-to-source manifest. Verify it from
the root without changing files:

```python
from pathlib import Path
import hashlib
import json

root = Path(".")
files = json.loads((root / "source-inventory.json").read_text())["files"]
for name, expected in files.items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
print(f"Verified {len(files)} distribution files")
```

The inventory excludes itself, private state and generated/dependency caches.
A maintainer creates a new release inventory after reviewing intended source or
documentation changes. Do not apply that operation to original result manifests,
execution seals or `formal/source-manifest.json` to hide a failed integrity check.
