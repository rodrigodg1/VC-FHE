# Linear verification

The current complete route is `../run-linear.sh`. Contracts implement enrollment, record admission and aggregate authentication. `npm ci` prepares the locked JavaScript dependencies. `npm run test:mklhs` runs component contract regressions. `run-experiment-output-binding.sh` is the older output-binding profile, with its own Rust lock and CSV/plot tools. Do not combine its measurements with the current grouped-radix threshold results.
