# Input datasets

The current runner downloads inputs using fixed revisions and SHA-256 checks in
`threshold-kms/campaign/datasets.py`. Raw inputs are not bundled here.

| Input | Current use | Acquisition |
| --- | --- | --- |
| STAV360 `Raw_Ratings.csv` | Linear subjective-rating aggregates | Pinned authors' mirror |
| 5G-QoERA BS1 and BS4, driver PRB 10 | Two nonlinear QoE compliance workloads | Pinned authors' repository, TSV converted to CSV |

STAV360 contains subjective ratings. 5G-QoERA combines mobility inputs with
simulated network performance and model-derived MOS. These are different data
sources and should not be described as equivalent direct measurements.

Before running, review the upstream access and reuse terms:
[STAV360](https://github.com/SLG-European-Projects/STAV360) and
[5G-QoERA](https://github.com/telematics-lab/5G-QoERA).
The STAV360 downloader explicitly notes that redistribution rights have not been
established. Downloading a file does not grant additional rights over it.

The full launcher acquires only its required inputs. `datasets/download/` also
contains optional component downloaders and `datasets/prepare/` contains their
preprocessing tools. Those broader component examples are not extra workloads in
the current full campaign. Prepared inputs are generated into `datasets/outputs/`
and remain untracked. Keep download hashes and preprocessing provenance with a run.

The campaign selects disjoint owner panels and records exact input and fixture
hashes. Do not replace inputs in an already measured run. Synthetic test inputs
must remain labeled synthetic and must not be used to fill missing dataset records.

## Selection and encoding

The [experiment guide](../docs/EXPERIMENTS.md) defines the rating aggregate and the
two compliance predicates, panel sizes and score/cell encodings. Exact source
revisions, paths, conversion and SHA-256 values are in
[`campaign/datasets.py`](../threshold-kms/campaign/datasets.py). For QoERA, the
checked digest refers to the converted CSV bytes. The controller aborts on a
changed existing file instead of overwriting it or substituting synthetic inputs.

Repository access and dataset permission are external prerequisites. If a pinned
upstream file becomes unavailable, obtain the identical permitted file and verify
its recorded checksum; do not silently switch to the upstream default branch.
Numerical replay of retained results does not require these raw input downloads.
