# Challenge incentives and funded settlement

This guide describes the implemented **bounty-v2 / bounded-cost-v1** game. It
separates contract-enforced transfers, conditional mathematical implications and
observed test-profile quantities. None of these establishes that an honest
party will always audit. Read [protocol execution](PROTOCOLS.md) for the evidence
and deadline rules on which settlement depends.

## Participants and choices

- An operator executes the authorized program or chooses a cheating strategy.
  A coalition can control both operator and auditor identities. Transfers between
  its own identities cancel when calculating its net payoff.
- A sampled auditor can abstain, perform the full replay, voluntarily commit and
  open an audit result, and pursue an eligible challenge. Registration alone is
  neither evidence of work nor a punishable obligation to work.
- The active challenger is the auditor recorded for the current dispute. Other
  auditors can lose the race even when they found the same fault.
- Adjudicators recompute and certify the isolated operation. Their soundness and
  availability are assumptions; the bounty contract does not fund their service.
- A disclosure requester pays the separate disclosure deposit. Anyone can relay
  authenticated data or bisection branches, without becoming the bounty recipient.

The economic model compares finite expected monetary payoffs for risk-neutral
participants in a one-shot game. All amounts must use the same currency. Costs
include computation, communication, transactions and capital lockup when relevant.
Cryptographic soundness does not require rational adversaries. Economic deterrence
requires a bounded external benefit and does not cover an attacker willing to
lose money solely to disrupt the system.

## What the contracts enforce

Let `D_o` be the reserved operator penalty, `R_c` the computational bounty and
`B_c` the auditor's reserved commitment/challenge bond. They are deposited funds,
not merely nominal penalties. A commitment's bond is reused on challenge
activation; the same money is not reserved twice. Concurrent obligations cannot
reuse reserved funds. Withdrawal is limited to unreserved stake above applicable
registration minima; full role retirement is not implemented.

| Outcome | Operator accounting | Challenger accounting / task outcome |
| --- | --- | --- |
| Certified operator-invalid, challenger-valid | Debit `D_o`; credit `R_c` to recorded challenger; remaining `D_o - R_c` irrecoverable | Bond returned; task rejected |
| Certified operator-invalid, challenger-invalid | Debit `D_o`, no bounty | Bond forfeited without compensation; task rejected |
| Certified operator-valid | Receive floor(`B_c / 2`) from failed challenge | Bond forfeited, remainder irrecoverable; author barred from another challenge on this task; task reopens |
| Authenticated malformed challenger evidence or attributable challenger nonresponse | Failed-challenge compensation where applicable | Bond forfeited; task reopens for other eligible auditors |
| Attributable operator default / unresolved disclosure failure | Reserved penalty forfeited | Active bond returned, **no computational bounty**; task rejected |
| Missing certificate after authenticated terminal admission | No computational verdict | Dispute remains pending; silence neither accepts the task nor awards a bounty |
| Uncontested accepted task | Operator reservation unlocked | Opened unused audit bonds can be reclaimed, no agreement reward |

“Irrecoverable” means removed from spendable balances with no withdrawal path in
the game, not an assertion that the chain's native currency supply is reduced.
Disclosure is accounted separately: complete authenticated publication credits
the disclosure deposit to the operator even if fraud is subsequently certified.
Failure to publish permits its refund. A claimable credit is not an observed
withdrawal.

An auditor's **voluntarily submitted but unopened** commitment can be penalized
after its opening deadline. Early task closure by that deadline permits its bond
return. A secondary report earns no reward or correctness penalty. Commit/reveal
binds evidence and identity before opening; it does not prove independent replay
or prevent private sharing.

Source: [CanonicalBountyFHEDisputeGame.sol](../fhe-pod/contracts/src/CanonicalBountyFHEDisputeGame.sol)
(`submitSealedAudit`, `_releaseChallengeBond`, `_applyLeafDecision`,
`_settleOperatorBond`, `timeoutDispute`, `claimAuditBond`, `slashLazyAuditor`,
`withdraw`) and [BountyTraceAvailability.sol](../fhe-pod/contracts/src/BountyTraceAvailability.sol).
Inherited authentication and reopening rules are in
[VerifiableFHEDisputeGame.sol](../fhe-pod/contracts/src/VerifiableFHEDisputeGame.sol).

## Why a valid active challenge can receive the bounty

Assume binding/authentication, deterministic evaluation under the admitted
profile, sound adjudication, complete authenticated records, timely relaying and
transaction inclusion, and live adjudication. For a structurally valid trace,
full replay identifies the first unequal instruction. Its predecessors coincide,
so both sides have the same operands and the canonical result fixes which claim
is valid. Authenticated bisection preserves that first difference.

The active first-difference challenger can relay both sides' authenticated
branches without another operator transaction. After terminal admission a sound
certificate reports operator-invalid and challenger-valid. The settlement rule
then credits that challenger and returns its bond. Reservation funds the payment;
terminal-state guards prevent a second payment for the resolved task. Missing
data, an earlier procedural rejection or an adjudicator outage can prevent this
path. A second correct contender has no entitlement to the active challenger's
bounty.

The model results are `Dispute.bounty_requires_both_results` and
`Dispute.admitted_bounty_settlement` in
[DisputeSafety.lean](../formal/VCFHE/DisputeSafety.lean). Conditional termination
is modeled separately in [Liveness.lean](../formal/VCFHE/Liveness.lean): each lost
challenge consumes one member of the finite cohort, each bisection reduces depth,
and productive transitions decrease a natural-valued measure. Eventual productive
progress is a premise, not a consequence of a financial reward.

## Operator deterrence: a sufficient condition

For one operator or coalition and one cheating strategy, define:

| Symbol | Meaning |
| --- | --- |
| `R_o >= 0` | Service payment earned only on successful completion; zero if absent; not enforced by the bounty contract |
| `C_o`, `C_fake` | Expected honest/cheating costs, net of other protocol receipts; disclosure enters here once |
| `B_o >= 0` | Bound on the additional benefit of accepted fraud |
| `P` | Strategy-specific probability of timely fraud-detecting settlement |
| `S_o` | Expected coalition settlement loss conditional on that settlement, excluding unpaid `R_o` and disclosure already counted in costs |

Assume honest completion. Assigning `R_o + B_o` even to unresolved cheating
outcomes produces an upper bound:

```text
U(honest) = R_o - C_o
U(cheat) <= (1 - P)(R_o + B_o) - P S_o - C_fake
U(honest) - upper_bound(U(cheat))
          = P(S_o + R_o) - (1 - P)B_o - (C_o - C_fake)
```

Thus `P(S_o + R_o) > (1 - P)B_o + C_o - C_fake` is sufficient for honest payoff
to exceed that strategy's cheating payoff. Dropping nonnegative `P R_o` gives a
more conservative sufficient condition. Deterrence over the strategy space
requires the condition for **every** admitted cheating strategy. The analysis
supplies no empirical lower bound on `P`. A colluding challenger recovers at most
`R_c` from `D_o`, so conditional settlement loss is at least `D_o - R_c` when the
other specified coalition transfers are accounted for.

`Economics.operator_gap` proves the identity and `deterrence_sufficient` the
implication in [Economics.lean](../formal/VCFHE/Economics.lean). They use integer
scalings of rational quantities; the probability interpretation additionally
requires a positive common denominator and probabilities in `[0,1]`.

## Challenging a detected fault is different from deciding to audit

After an inconsistency is observed, let `p_R` be the probability of receiving
`R_c`, `p_B` the probability of losing `B_c`, and `C_chal` the expected **additional**
cost. Prior costs are sunk. Relative to abstention, challenge payoff is positive
exactly when:

```text
p_R R_c > C_chal + p_B B_c
```

These probabilities need not sum to one. A procedural rejection can return the
bond without paying a bounty; an unresolved case can leave it locked. The active
challenger under the settlement conditions above has `p_R = 1`, `p_B = 0`, giving
`R_c > C_chal`. Correct adjudication by itself does not establish these probabilities.

Before replay, let `p_win` include fault occurrence, competition and timely
settlement; `C_a` is expected monitoring/replay cost; `C_d` covers other expected
participation costs; `L_a` is expected bond forfeiture. With only bounty income:

```text
U(audit) = p_win R_c - C_a - C_d - L_a
U(audit) > U(abstain) = 0  iff  p_win R_c > C_a + C_d + L_a
```

Returned principal is neither income nor expense. With no expected fraud or
other benefit, positive audit costs make fault-only participation unprofitable.
The respective lemmas are `challenge_profit_iff`, `participation_profit_iff` and
`no_fault_no_profit`. Neither inequality establishes an equilibrium, fair
selection, Sybil resistance, sustained auditing or honest audit coverage.

## Declared bounded-cost calibration

For a maximum trace size `L_max`, let `F_max` bound disclosure charges and `C_bar`
budget all other winning-audit costs, including full replay. The constructor
requires:

```text
R_c > F_max + C_bar
D_o > R_c + F_max
```

A winner with actual `F <= F_max` and `C <= C_bar` has `R_c - F - C > 0`.
Even if outsiders fund disclosure that benefits an operator/challenger coalition,
its loss from settlement and that receipt is at least
`D_o - R_c - F_max > 0`. These are `winning_margin` and `coalition_loss`.
Declared bounds are enforced; actual off-chain cost bounds are not proved by
constructor checks. Long delays can exceed a capital-locking budget.

The [functional test inputs](../fhe-pod/scripts/bounty-economics.json) give, in
chain-native units (10^18 wei per unit): `L_max=512`, `F_max=1.044`,
`C_bar=0.25`, `R_c=1.544`, `D_o=3.338`. Winning surplus within budget is at least
`0.25`; residual coalition loss after the maximum disclosure credit is `0.75`.
These are calibration quantities, not market prices or measured economic profits.
Reproduce their exact integer calculation from the repository root:

```bash
node --input-type=module -e 'import { BOUNTY_TEST_ECONOMICS as e } from "./fhe-pod/scripts/bounty-economics.mjs"; console.log(JSON.stringify(e, null, 2))'
node --test fhe-pod/contracts/test/bounty-economics.test.mjs
```

For an illustrative participation calculation, a hypothetical net winning reward
of `0.5` and hypothetical `p_win=0.01` allow **less than** `0.005` expected remaining
cost per audit. At `p_win=0`, any positive remaining cost defeats this condition.
This example is not a measured probability or cost recommendation.

## Measurements and verification

[The 18 distributed economic records](../results/distributed/workflow/economics.json)
contain successful-dispute transfers, mined gas fees and explicit unpriced costs.
The retained test-chain gas fee is zero; gas usage is not zero, and neither compute
nor infrastructure becomes free. Reward after disclosure and fees is a residual
**before** unpriced replay, capital, retry and service costs. The experiments did
not estimate `p_win`, spontaneous participation or strategic equilibrium.

The older `fhe-pod/scripts/analyze_game_theory.py` also contains a legacy
mirror/diligence-reward model. That portion does **not** describe bounty-v2:
`claimDiligenceReward` is disabled and no correctness penalty applies to unused
secondary reports. Use the current equations, contracts and Lean module above
for this profile; do not present the legacy figure as its incentive validation.

From `formal/`, run `python3 check.py` and `python3 test_verifier.py` with Lean
4.19.0. From the root, after installing `fhe-pod` dependencies, run
`npm --prefix fhe-pod run test:canonical-bounty` on the default isolated in-process
EVM, with `VCFHE_TEST_RPC_URL` unset. Its fixture tests check reservations,
settlement, abandonment, relays and negative cases, not real FHE or rational
behavior. [Formal correspondence](../formal/SOURCE_CORRESPONDENCE.md) connects
model premises to source guards. It is a reviewed mapping, not a machine-checked
refinement proof for the Solidity/Rust executables.
