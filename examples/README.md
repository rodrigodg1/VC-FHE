# Component examples

Examples exercise selected components and do not inherit the current threshold
campaign's evidence. [Linear application examples](linear-applications/README.md)
are retained for inspection: their inherited `lib/scenario.mjs` is missing, so
those demo/test commands are unavailable. The [expression toolkit](../toolkit/README.md)
has its own compiler tests and explicit operation list. Its outputs alone are not
proof of FHE execution or authorized output recovery.

The [arithmetic example](exemplo-aritmetico/) explains the calculation
`total = x + y * z` through a two-operation trace. From the repository root,
`DRY_RUN=1 examples/exemplo-aritmetico/run-arithmetic-demo.sh` checks and prints
the trace. The [full RQUAL example](../Anatel/anatel-rqual/) and
[simplified RQUAL example](../Anatel/anatel-rqual-simplificado/) are grouped under
`Anatel/`.

For supported complete execution use [local reproduction](../REPRODUCE.md) or
[Google Cloud reproduction](../distributed/GOOGLE-CLOUD.md). Historical aliases
in component packages are not additional supported experiment routes.
