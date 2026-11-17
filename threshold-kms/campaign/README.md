# Campaign controller

Use the root launchers, which select the supported Test PoC, initialize only a
truly empty policy installation, check dependencies and preserve existing state.
`run.py --help` documents the low-level selector. Nondefault profiles are explicit
component or historical routes and need their own matching evidence.

Stages cover pinned build, Besu, on-chain policy, four KMS participants, PRSS,
preprocessing/DKG, owner encryption, selected workloads, validation and export.
`poc_plan.py` fixes the paired/full-case design. `poc_evidence.py` validates it.
`onchain_evidence.py` checks exact release and counter evidence. Stage records,
source closures, receipts and seals distinguish complete cases from partial work.

`--postprocess-only` delegates to `postprocess/refresh.py` without executing the
campaign. `--check` validates retained original evidence. `--list` and `--preflight`
are inspection routes. See [the local guide](../../REPRODUCE.md).
