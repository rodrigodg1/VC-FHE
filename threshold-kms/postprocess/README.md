# Validate and derive a completed run

Use `./run-poc.sh --postprocess-only --run-dir threshold-kms/runs/RUN_ID` from the
repository root. This performs no protocol operation. It validates the original
run, creates provenance, checks paired-data diagnostics, derives per-stage
observations and renders numerical tables and plots.

The default plotting environment is `threshold-kms/.cache/postprocess-python/`,
with versions in `requirements.txt`. A fresh analysis destination must be a direct
child of `threshold-kms/composites/`. `--derived-dir` selects it. Existing mismatched
provenance is refused. Preserve incomplete attempts instead of overwriting them.

`--manual-review` produces `diagnostic-review-template.json` when review is absent.
Complete its checks against the bound diagnostic files, then pass the completed
file through `--diagnostic-review`. Without that option, automated review records
only its implemented checks and stops when those conditions fail. Do not invent
an approval record for failed diagnostics.

`analysis-package.json` binds the selected scope, provenance, renderer and outputs.
`validate_derived()` checks the original run again and verifies that package.
`results-ready` means the derivation completed. It does not claim a new experiment.

Distributed runs use guarded copies made by `distributed/postprocess_adapter.py`.
They retain the 480-pair/18-warm-up design and adapt full-case counts from five to
three per configuration. Original local generators are not modified by that step.

For public numerical replay without raw execution state, use
[results/reproduce.py](../../results/README.md). Its verification scope is smaller:
it checks retained numbers and hashes, not live chain/KMS records.
