# Numerical collection dictionary

Use `distributed/` for the current geographic observations and `local-archive/`
for the separate historical local run. Never join them as repeated samples of
one configuration. All paths below are relative to the selected collection.
Run `python3 results/reproduce.py` from the repository root before analysis.

## Tables and identifiers

| File / field | Meaning |
| --- | --- |
| `collection.json` | Expected SHA-256 per included file and design counts; a numerical manifest, not a raw execution seal |
| `setup.json` | Hardware, topology and measurement-profile scope; absent host fields are not inferred |
| `workflow/observations.csv`: `case`, `group`, `half`, `n` | Case ID, configuration, linear/nonlinear path and input count |
| `cohort`, `step`, `metric`, `unit`, `value` | Measurement scope, stage and quantity; keep all grouping keys when aggregating |
| `source` | Relative provenance reference, often a JSON pointer into original evidence; not a downloadable URL |
| `workflow/summary.json`: `metrics` | One row per group/half/n/cohort/step/metric/unit, with count, mean, sample SD, min/max |
| `diagnostics/paired-observations.csv` | One paired comparison per row, including method order and warm-ups |
| `workflow/receipt-partition.csv` | Per-transaction gas, calldata, block and accounting boundaries |
| `workflow/economics.json` (distributed) | Successful challenged-case reward/penalty/fee records and unpriced cost list |
| `cpu-inputs/` (distributed) | Compressed process records for CPU budget reconstruction |
| `case-origins.json` (distributed) | Case-to-segment mapping and source hashes |

`cohort` distinguishes paired/full work and other recorded boundaries. Do not
assume every observation row is an independent experiment. A case contributes
multiple stage/metric rows. A `setup-once` value is not a per-case cost without
an explicitly chosen amortization model. Warm-up case names and flags are
separate from the 480 measured pairs.

In the paired table, `repeat`, `ordinal`, `order`, `warmup` and `fullCase` retain
selection and sequence information. CSV flags are strings `True`/`False`, not
Python booleans until parsed. `fixtureDigest` identifies the input fixture binding;
`scope` qualifies the timer. `wallStarted`/`wallFinished` identify observation time;
`proposed_ms`, `baseline_ms`, `operator_ms` and `shared_preparation_ms` are distinct
elapsed quantities, not disjoint intervals to add blindly.

Receipt fields include `gasUsed`, `calldataBytes`, `effectiveGasPriceWei`,
`transactionFeeWei`, `valueWei`, `sender`, `recipient`, `block`, `cohort`,
`boundary` and `label`. Wei-valued fields require exact integer/decimal arithmetic.
A transfer's `valueWei` is principal, not gas expense. Empty recipient fields can
represent contract creation. Opaque identifiers preserve joins without exposing
original accounts or transaction hashes.

## Missingness and financial quantities

- Missing values remain missing. Sample SD is null for a single observation.
- Milliseconds, gas units, bytes and wei must not be combined without a stated
  conversion. A zero test-chain fee does not mean zero gas or zero infrastructure
  cost. Cloud charges are distinct from the economic test currency.
- The economic reward residual excludes explicitly unpriced off-chain work,
  capital lockup, retries and service compensation. It is not observed profit.
- Summed CPU includes only the processes named in the derived budget. Remote
  handler delay can overlap computation and network transfer. Host NIC counters
  include traffic beyond role-level serialized requests.

## Read and filter without changing inputs

This Python example uses only the standard library and preserves exact integer
values through JSON numeric decoding. Run it from the repository root:

```python
from collections import Counter
import csv
import json
from pathlib import Path

base = Path("results/distributed")
with (base / "workflow/observations.csv").open(newline="") as stream:
    rows = list(csv.DictReader(stream))
full = [r for r in rows if r["cohort"] == "full"]
assert len({r["case"] for r in full}) == 27
print(Counter(r["half"] for r in rows))  # observation rows, not workflow counts
values = [json.loads(r["value"]) for r in rows]  # keep each row's metric and unit
assert len(values) == 8392
```

For Pandas users, import wei/account identifiers as strings and convert individual
integer columns explicitly; a general float cast can lose wei precision. Group
by all semantic keys and inspect each denominator. Choose a new derived output
directory; never overwrite the collection or edit its manifest to accept changed
inputs. The [reproduction script](reproduce.py) implements full numerical checks,
including receipt endpoints and process CPU reconciliation.

## Integrity scope and completeness

A matching collection hash verifies identity with the distributed numerical
manifest. It is not an independent proof that the original cloud writer produced
correct measurements. Statistical reconciliation verifies the local relationship
between observations and summaries. Raw-run validation additionally needs the
original source closure, binaries, ciphertexts, private state and native evidence.

This curated collection covers all 27 full workflows and the complete paired grid,
but is not an archive of every host log, transport journal or historical cloud
snapshot. Some auxiliary fields were sanitized or omitted. The collection must
not be used to claim complete recovery of all cloud files or to authorize deletion
of another run's original evidence. [Storage guidance](../distributed/STORAGE.md)
defines those separate preservation checks.
