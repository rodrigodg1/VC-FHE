# Contributing

Keep protocol changes separate from measurement and documentation changes.
Describe the trigger, resulting behavior, assumptions and checks performed.
Use synthetic data for regression tests. Preserve dependency locks and existing
negative cases. A change to protocol rules, compilation, canonical execution or
cost-bearing code requires fresh matching execution evidence before its results
can replace older measurements.

Run [the relevant checks](docs/DEVELOPMENT.md) and the public-source audit. Do not
commit secrets, consumed policy state, live deployment metadata, raw datasets or
build caches. Preserve failed experiments and do not rewrite their seals.
