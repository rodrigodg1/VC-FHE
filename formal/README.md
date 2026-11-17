# Machine-checked protocol proofs

This package contains 70 named lemmas and theorems in Lean 4: 43 for canonical
nonlinear verification and owner-authorized result release, and 27 for linear
binding arithmetic, grouped conversion, audit privacy, payoff inequalities and
conditional liveness. The proofs cover arbitrary finite traces, quorum sizes
and policy executions, with the numerical bounds and component hypotheses stated
in each theorem. The package uses Lean's bundled `Std` library and the pinned
toolchain in `lean-toolchain`.

The proof level is **protocol transition models and mathematical component lemmas**. The
[source correspondence](SOURCE_CORRESPONDENCE.md) records the reviewed mapping
from model premises and transitions to contract and KMS code. Source hashes bind
that mapping to the reviewed files. Cryptographic binding, authenticated identities,
FHE correctness and threshold-KMS correctness are explicit component interfaces.

For the economic definitions, payoff derivations, settlement branches and worked
calibration example, read [challenge incentives](../docs/INCENTIVES.md). The
[guarantee map](../docs/EVIDENCE.md) links the other models to tests and measurements.

## Reproduce the verification

Install [Lean 4.19.0](https://github.com/leanprover/lean4/releases/tag/v4.19.0)
using a standard Lean installation, then run from this directory:

```bash
python3 check.py
```

The same commands apply to each repository's `formal/` directory. A successful
run reports `PASS: 70 theorems; 14 modules; Lean --trust=0; standard axioms only`.
The verification needs Python and the pinned Lean toolchain; it uses no external
Lean packages, SMT solvers, blockchain services or cryptographic experiment data.

Python 3.10+ is sufficient. An existing standalone installation can be selected
with `--lean /absolute/path/to/lean` or the `LEAN` environment variable. The check
uses a fresh build directory, verifies the mapped source hashes, compiles every
module with `lean --trust=0`, and audits every named theorem with `#print axioms`.
It also exports the complete theorem types. `lake build` is available for normal
Lean development; `check.py` additionally performs the source and axiom audits.

The axiom audit permits only Lean's standard logical axioms: `propext`,
`Classical.choice` and `Quot.sound`. All protocol and cryptographic hypotheses
are theorem parameters. The source gate rejects unfinished proofs, custom axiom
declarations and native proof shortcuts.

To retain a new verification report explicitly:

```bash
python3 check.py --output evidence
```

The retained [validation report](evidence/validation.json),
[axiom inventory](evidence/axioms.txt), [theorem types](evidence/theorems.txt) and
[commands](evidence/commands.json) identify exactly what was checked.

The verifier's [rejection controls](evidence/verifier-tests.json) can also be
reproduced in temporary copies:

```bash
python3 test_verifier.py --output evidence/verifier-tests.json
```

The seven controls exercise rejection of an unfinished proof, an added axiom,
a false arithmetic proof, a changed source file, a five-member radix group,
noise at the rounding boundary and reuse of a defeated challenger. The last
three deliberately weaken conditions of the component lemmas. The original
sources are read-only throughout these controls.

## Results

| Property | Principal theorem | Mathematical scope |
| --- | --- | --- |
| First differing instruction is invalid | `Canonical.first_difference_invalid` | Fixed authenticated program, prefix dependence and deterministic evaluation |
| Bisection isolates the first difference | `Bisection.detection_and_localization` | Any power-of-two trace length; faithful authenticated subtree comparisons |
| A certificate contains an honest signer | `Quorum.honest_signer_exists` | Distinct authenticated signers; corruption count strictly below quorum |
| Approval count represents all required owners | `Quorum.full_count_all_true` | One Boolean approval flag per distinct owner |
| A pursued valid challenge prevents acceptance | `Dispute.challenge_blocks_acceptance` | Authenticated evidence, timely challenger, sound certified leaf decisions |
| Accepted traces equal canonical execution | `Dispute.conditional_trace_soundness` | Explicit audit-coverage witness and the leaf-validity interface |
| Bounty beneficiary and result conditions | `Dispute.bounty_requires_both_results` | Active bound challenger, operator-invalid and challenger-valid decision |
| Settlement path from authenticated evidence | `Dispute.admitted_bounty_settlement` | Evidence admission followed by a sound certificate; neither transition requires a new operator action |
| Authorization, unique reservations and cumulative budgets | `Release.reachable_invariant` | One policy deployment, stable registered records, arbitrary approval/reservation sequences |
| Threshold recovery requires authorization and output binding | `Release.threshold_release_bound` | Honest responder duties, fixed finalized state and required delivery/conversion validation |
| Correct recovered plaintext | `Composition.released_plaintext_correct` | Composition of nonlinear soundness, authorization, output binding, FHE and KMS correctness |
| Five-event error bound | `EndToEnd.nonlinear_plaintext_error_bound` | Finite outcome lists with arbitrary natural weights; no independence premise |
| Commitment collision yields a relation | `Linear.collision_exposes_relation` | Subtraction homomorphism and cancellation; a distinct opening produces a nonzero kernel relation |
| Linear accumulation and signed reduction | `Linear.homomorphic_accumulation`, `Linear.signed_reduction` | Finite weighted vectors and an integer sum strictly within the centered field interval |
| Grouped radix conversion preserves value | `GroupedConversion.carry_conservation`, `GroupedConversion.group_capacity` | Base-four propagation; at most four prepared digits plus an incoming carry of at most three |
| Conversion size and arithmetic bounds | `GroupedConversion.subtotal_fits`, `GroupedConversion.interval_subtraction` | At most 33 records bounded by 511; eight base-four blocks and an admitted nonnegative result |
| Deterrence and positive audit surplus | `Economics.deterrence_sufficient`, `Economics.winning_margin` | Strategy-specific payoff bound, declared costs and positive reward margin |
| Public audit transcript simulation | `AuditPrivacy.public_simulator_exists` | Each operation is independent of an additional FHE secret given its public state and randomness |
| Conditional eventual finalization | `Liveness.eventual_finality` | Finite challenger cohort, spent losing challenges, finite bisection and eventual productive transitions |

The policy invariant proves six properties together: bounded counters, exact
accounting against reservation history, authorization of every reservation,
unique request identifiers, unique request keys and unique slots. Accounting
uses stable record identifiers across tasks. Reservations remain consumed when
subsequent delivery fails.

For the probability result, divide all weighted event masses by the same positive
total weight. This yields the bound for finite rational probability experiments:
incorrect recovery is bounded by missing audit coverage plus binding,
certification, FHE and KMS failure probabilities. The final theorem derives the
correctness implication from the execution and release proofs before applying
the union bound. Numerical failure rates remain parameters of the component
security assumptions.

`AssumptionWitnesses.lean` supplies concrete authorized executions and certified
rejection witnesses. It also records guard-necessity witnesses: uncovered
optimistic acceptance, a fully corrupted signing set, exhausted budgets with the
budget guard omitted, and a changed recipient. The modified-guard example
describes that modified model; the actual policy retains the guard.

## The 27 component lemmas

| Module | Named results | Coverage |
| --- | ---: | --- |
| [Linear](VCFHE/Linear.lean) | 6 | Collision-to-relation implication, homomorphic accumulation, centered lifting, signed reduction and the strict decoding cell |
| [GroupedConversion](VCFHE/GroupedConversion.lean) | 9 | Carry conservation, degree/digit/noise capacity, subtotal size, final subtraction and SUM/SUB layout bounds |
| [Economics](VCFHE/Economics.lean) | 7 | Operator payoff difference and sufficient deterrence, challenge and participation profit, winning surplus, coalition loss and zero-reward loss |
| [AuditPrivacy](VCFHE/AuditPrivacy.lean) | 2 | Composition of public-only operations and existence of a transcript simulator |
| [Liveness](VCFHE/Liveness.lean) | 3 | Decreasing progress measure, absence of infinite descent and eventual finality under productive progress |

The linear relation lemma supplies the algebraic implication used with DLR;
computational hardness and signature security are cryptographic interfaces.
Carry conservation first retains the final carry; the separate size bound
justifies representing admitted subtotals in eight blocks. Noise capacity uses
the declared nominal levels, with correctness of FHE operations supplied by the
component interface.

The economic lemmas express exact polynomial identities and inequalities over
integers. Multiplying rational probabilities and monetary amounts by common
positive denominators gives this representation without changing inequality
directions. Strategy probabilities, actual cost bounds and expected receipts
are inputs; profitable participation follows when the corresponding inequality
holds.

The privacy lemmas establish composition for operations satisfying `PublicOnly`.
Public ciphertexts, metadata, authorized outputs and independent authentication
material belong to the supplied state/randomness. The source correspondence
identifies the public audit paths supplying that interface. Threshold-protocol
security and the entropy bound on authorized responses have separate arguments.

The liveness model compresses finite waiting periods into productive transitions.
Its `live` premise supplies eventual disclosure, inclusion and adjudication.
Removing a losing challenger and reducing the bisection depth then force
eventual finalization. Timely participation remains the stated progress premise.

## Interpretation

The mechanization addresses logical implication from the stated protocol and
component premises. The correspondence review links those premises to source
guards and participant duties; the repository's regression suites exercise the
implementation separately. The proof terms establish the model theorems, while
the source mapping records the specification-to-implementation review.

Audit coverage is an explicit execution condition. Certificate safety uses a
corruption threshold; progress also requires timely participation and transaction
inclusion. The settlement theorem constructs the certificate path once its
evidence is available. The liveness model proves termination under productive
progress, and the economic lemmas verify the payoff implications under their
probability and cost conditions. Actual participation, financial transfers,
blockchain consensus, FHE security and malicious threshold cryptography retain
their respective implementation or component-security evidence.

For linear output release, the contract authenticates the aggregate and its
registered inputs. Owners and the recipient validate the required conversion
and delivered ciphertext. `Release.OutputBound` expresses that additional
interface separately from the on-chain reservation guard.

The verification commands compile proof files and read the pinned sources. They
do not start blockchain/KMS services or consume decryption slots.
