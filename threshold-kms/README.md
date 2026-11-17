# Threshold-KMS campaign

The supported end-to-end route is `../run-poc.sh`, executed from the repository
root as `./run-poc.sh`. Independent selectors run linear or nonlinear work.
[Local reproduction](../REPRODUCE.md) defines prerequisites, pilots, counts,
validation and state handling.

`campaign/` controls source-bound Docker builds, four-core setup, owner encryption,
paired measurements, full workflows and original evidence checks. `contracts/`
contains the grouped linear verifier and all-owner output-release policy.
`scripts/`, `src/` and `patches/` connect the pinned Zama KMS with exact request
bindings and recipient validation. `postprocess/` derives numerical results after
validation. `recovery/` has profile-specific historical continuation tools.

The current route uses Test parameters, TFHE-rs 1.6.1 and the pinned upstream KMS
v0.13.20 source. The local cryptographic profile and native cloud recipient adapter
are recorded separately. Never substitute private key material or claim secure
parameter performance from Test runs. The older integration entry points are
component development tools, not substitutes for the complete current campaign.
