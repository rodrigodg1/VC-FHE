# Technical documentation

Read the following in order for a first independent review. Commands are run
from the repository root unless a guide explicitly changes directory.

1. [Architecture and component responsibilities](ARCHITECTURE.md).
2. [Protocol flows and failure branches](PROTOCOLS.md).
3. [Challenge incentives, derivations and settlement examples](INCENTIVES.md).
4. [Guarantees and evidence map](EVIDENCE.md), then [Lean models](../formal/README.md)
   and [security assumptions](SECURITY.md).
5. [Experiment design and reproduction targets](EXPERIMENTS.md),
   [datasets](../datasets/README.md), [circuit correctness](compliance-circuit-correctness.md), [metric boundaries](METRICS.md) and
   [numerical data dictionary](../results/DATA-DICTIONARY.md).
6. Choose [offline numerical reproduction](../results/README.md),
   [local execution](../REPRODUCE.md), or [Google Cloud execution](../distributed/GOOGLE-CLOUD.md).
7. Consult [development checks](DEVELOPMENT.md) and [validation status](VALIDATION.md)
   for executed checks and the limits of each validation route.

The public directory is self-contained for source inspection and numerical
reproduction, subject to the listed external toolchains. Private original runs
are not bundled. Historical component examples and source-specific recovery tools
have separate scopes; they are not shortcuts around the supported entry points.
