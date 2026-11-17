# Nonlinear computation

The current complete route is `../non-linear.sh`. This component contains the explicit circuit compiler, canonical ciphertext executor, trace/dispute contracts, public audit workers and negative tests. Use `npm ci` here before Node checks. `npm run test:lowering` checks explicit circuit lowering without cloud resources. Other contract/FHE commands are listed in `package.json`. Older demonstration and legacy evaluation commands have different assumptions and do not replace the threshold campaign.

For current semantics read [protocols](../docs/PROTOCOLS.md) and
[incentives](../docs/INCENTIVES.md). `npm run test:canonical-bounty` uses an isolated
in-process EVM by default; leave `VCFHE_TEST_RPC_URL` unset to avoid an external
chain. Tests use fixture ciphertext handles/certificates and do not execute a
measured FHE experiment. `node --test contracts/test/bounty-economics.test.mjs`
checks declared budget arithmetic without starting any service.

The historical `analyze_game_theory.py` includes a mirror/diligence-reward model
not implemented by bounty-v2. The component aliases `demo:anatel`,
`demo:anatel-simplified` and `demo:arithmetic` point to the
[full RQUAL example](../Anatel/anatel-rqual/),
[simplified RQUAL example](../Anatel/anatel-rqual-simplificado/) and
[arithmetic example](../examples/exemplo-aritmetico/). Append `-- --dry-run`
to these npm commands to inspect their traces. Their full demonstration routes
retain their component-specific execution assumptions.
