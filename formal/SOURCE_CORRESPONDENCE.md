# Protocol-to-source correspondence

The mapping below was reviewed against the files in
[`source-manifest.json`](source-manifest.json). `check.py` verifies their hashes
before and after checking the proofs. This is a reviewed correspondence between
the mathematical specification and source rules. The Lean kernel checks the
formal models and their proof terms.

## Canonical execution and localization

| Formal object | Source rule | Interface supplied to the proof |
| --- | --- | --- |
| `Canonical.PrefixDependent` | `compliance-circuit.mjs`: `validateCircuit`; `canonical-protocol.mjs`: execution context and canonical recomputation | Inputs, constants, opcode, profile and evaluation material are fixed; output references point only to earlier instructions |
| `Canonical.Valid` | `canonical-protocol.mjs`: `canonicalTrace`, `detectCanonicalFault`, `adjudicateCanonicalLeaf` | Each result is the pinned evaluator's deterministic ciphertext result |
| `Bisection.locate` | `VerifiableFHEDisputeGame.sol`: `submitBisection` and bisection advancement; `experimental-public-replay.mjs`: `firstDivergence` | Follow the left unequal subtree; otherwise follow the right one |
| Faithful subtree comparison | Authenticated Merkle openings and the trace-binding premise | Equality of compared authenticated subtree hashes represents equality of their records for this execution |

The hash premise is an execution-level binding condition. The model does not
postulate global injectivity of a finite-output hash function. A ciphertext is an
abstract value; equality represents the prescribed serialized-byte equality.
Prefix dependence and reference validity are separate hypotheses. Plaintext
correctness additionally uses admitted inputs, range safety and task-level FHE
correctness.

## Certificates and dispute transitions

| Formal object | Source rule | Correspondence |
| --- | --- | --- |
| Distinct certificate indices | `CanonicalLeafVerifier.sol`: constructor and `_quorum` | Registered identities are unique; repeated recovered signers do not increase the count |
| `Quorum.certified_value_eq` | Bound EIP-712 context and leaf result; honest adjudicator recomputation | Under authentication, at least one of the counted signers is honest when `f < q` |
| `Rules.evidenceValid` | `_validateLeafResolution`, authenticated branch/leaf admission, context and provenance rules | Both openings and the isolated operation belong to the committed traces; malformed candidate evidence cannot claim this predicate |
| `Step.open`, `Step.relay`, `Step.admit` | `openChallenge`, `submitBisection`, `settleLeafViaAttestedDecision` | One active challenger is retained while authenticated evidence is relayed and admitted |
| `Step.malformedChallenge`, `Step.challengerDefault` | Challenger failure handling and `timeoutDispute` | A malformed or late challenger can lose and reopen the task |
| Certified transitions | `CanonicalBountyFHEDisputeGame.sol`: `_applyLeafDecision` | Operator-valid reopens; operator-invalid rejects; a bounty additionally requires challenger-valid |
| `Step.wait` in the admitted phase | Pending canonical leaf decision | Certificate absence preserves the pending dispute |
| `Step.finalize` | `finalizeUnchallenged` | Acceptance occurs from the auditing phase, with no active admitted dispute |
| Procedural rejection | Availability/default handling and `_rejectOperatorForProcedure` | Rejection without a computational bounty |
| Rejected terminal state | Finalized-state guards | Subsequent transitions cannot reopen or pay the same resolved task again |

`Step` abstracts already authenticated interfaces. Deadline arithmetic,
eligibility, bonds and availability restrict concrete calls. The safety model
admits additional opens, waits and procedural rejections; its protected-claim
invariant proves that a valid pursued invalid-transition challenge cannot reach
acceptance even in that more permissive transition relation.

`Covered` provides the execution suffix after a valid first-difference challenge
becomes active. For an accepted task, this is the relevant consequence of timely
honest audit coverage. It includes evidence validity and timely pursuit. The
model therefore distinguishes audit participation, certificate safety and
progress. It allows pending disputes to wait indefinitely; the settlement
theorem separately constructs the admission/certificate path under available
evidence and live submission.

The beneficiary in `Phase.rejected (some auditor)` records the computational
bounty entitlement. Exact collateral amounts and transfers are governed by
`_settleOperatorBond`, `_releaseChallengeBond` and their regression tests.

## Release authorization and cumulative limits

| Formal object | Source rule in `OnChainReleasePolicy.sol` | Correspondence |
| --- | --- | --- |
| Fixed `Config.terms` and registered owner map | `registerProtectedRecord`, `createConsent` | Owner-bound record identifiers, immutable registered terms, distinct protected records and distinct required owners |
| `Terms.context` | Consent statement and its digest | Chain/policy, workflow/task, program/profile, keyset/epoch/MPC context, ordered inputs and output type are bound together |
| `Request` | `ReleaseRequest`, `releaseStructHash`, `releaseAuthorizationDigest` | Exact request ID/key, ciphertext/aggregate, recipient key, wire/query digests and recipient are authenticated |
| Consent and exact-approval flags | `approveConsent`, `approveRelease` | Authenticated owner transaction; one approval per owner for that object |
| All-owner guard | `requiredOwnerCount`, approval counts and membership flags | Counts increase once for distinct listed owners; `Quorum.full_count_all_true` gives the Boolean counting implication |
| `Config.chainFinality` | `_hasFinality`, `_hasLinearFinality`, `_hasNonlinearFinality` | Finalized workflow and path-specific accepted output/context evidence |
| `Guard` and `reserve` | `reserveRelease` | Exact approval, recipient signature, unused request key and slot, available budget; atomic irreversible reservation |
| Reservation history | Reserved release state plus request-key/slot mappings | Proof-only history records successful reservation events; its projections are the persistent consumed identifiers |
| `charge` | Per-record `spent` increments | Each distinct contributing record is charged once per reservation, including across tasks |

Record registration fixes the owner used by the approval rules. The identity of
the underlying real-world data owner is a deployment/admission assumption.
Counters are scoped to one policy deployment. New tasks and key contexts retain
the same protected-record identifiers. The mathematical counters are natural
numbers; the concrete guarded increments remain within the configured integer
limits.

The model retains the resulting approval flags and reservation history and
abstracts proposal bookkeeping. A successful reservation supplies exactly the
authorization facts established by those flags and proposal bindings. Approval
monotonicity reflects the policy's absence of revocation.

### Output and KMS interfaces

`Release.Authorized` contains the on-chain authorization facts.
`Release.OutputBound` additionally identifies the accepted ciphertext and the
required delivery/conversion validation. For nonlinear execution,
`_matchesNonlinearBinding` binds the final output to the accepted task. For linear
execution, `_hasLinearFinality` authenticates the aggregate and inputs, while
owners/recipient verify the public conversion before exact approval and recovery.
This distinction is preserved in `threshold_release_bound` and the composed
plaintext theorem.

`threshold-kms/src/onchain_release.rs` derives authorization fields from the exact
received request, authenticates the configured chain/policy, observes state at
one fixed quorum-supported block and consumes a durable marker before MPC
participation. `owner-chain-quorum.mjs`, `workflow-auth.mjs`,
`kms-request-adapter.mjs`, `linear_release.rs` and `recipient_validation.rs`
implement the corresponding observation, binding and recipient duties.

The abstract quorum theorem uses distinct authenticated responders. The honest
responder rule is observation of the exact reserved request at the agreed
finalized state. Recovery and response binding are supplied by the threshold-KMS
interface; plaintext correspondence is supplied by `KMSOK.responseCorrect`.
`Quorum.threshold_feasible` separately states the arithmetic requirement for
both `f < q` and `q ≤ n-f`.

## Composition and probability

`Composition.released_plaintext_correct` connects canonical trace equality to the
accepted output, the authorized request and the recovered plaintext.
`EndToEnd.nonlinear_plaintext_error_bound` instantiates that theorem for each
outcome satisfying the binding, certification, coverage, FHE and KMS interfaces.
It then derives event containment and the five-term weighted union bound.

The probability model is a finite outcome list with natural weights. Repeating
an outcome or assigning unequal weights is supported. Dividing every mass by
one common positive total gives finite rational probabilities. The proof uses
no independence premise and does not estimate component failure rates.

The machine-checked claims are the named model theorems listed in
[`evidence/theorems.txt`](evidence/theorems.txt). Source correspondence and
regression evidence serve the distinct task of relating these mathematical
interfaces to the implementation.

## Linear commitment arithmetic

| Formal object | Source rule | Interface supplied to the proof |
| --- | --- | --- |
| `Linear.collision_exposes_relation` | `MKLHS-Verification.sol`: `admitRecord`, `verifyBound`, `submitResultBound`; recipient commitment comparison | A different delivered vector with the same linear commitment exposes a nonzero relation among the generators |
| `Linear.homomorphic_accumulation` | `admitRecord`: fixed SUM/SUB signs and one admission per index | Commitment preserves zero and addition; the list contains the weighted authenticated vectors |
| `Linear.balanced_lift_exact`, `Linear.signed_reduction` | `compatible_fhe.rs` and `linear_release.rs`: `normalize` | Canonical Fr coordinates, a sum strictly within the centered interval, then native-modulus reduction |
| `Linear.strict_decoding_cell` | Declared leveled-LWE message and noise budgets | Strict noise magnitude below half the decoding scale keeps the phase inside its intended cell |

The commitment theorem derives a nonzero kernel relation; it does not assume
global injectivity of the commitment. Computational DLR hardness and BLS
authentication provide the separate cryptographic interfaces. The deployment
tags in `MKLHS-Verification-v3.sol` and `GroupedLinearVerification.sol` bind the
authorized profile. The on-chain commitment equality is combined with recipient
verification of the delivered vector. Honest owner preparation supplies the
relation between each authenticated commitment and its input ciphertext.

## Grouped conversion

| Formal object | Source rule | Correspondence |
| --- | --- | --- |
| `GroupedConversion.carry_conservation` | `compatible_fhe.rs`: `prepare`, `normalize`; `linear_release.rs`: `normalize` | Base-four propagation preserves the represented integer, retaining the top carry in the mathematical identity |
| `group_capacity`, `digit_range`, `group_noise_capacity` | Groups of at most four prepared blocks; degree and nominal-noise admission before propagation | Degree at most 12 plus carry at most 3 fits capacity 15; nominal noise plus carry stays at most 5 |
| `subtotal_fits`, `no_top_overflow`, `interval_subtraction` | `Plan.validate`, eight-block representation and final positive-minus-negative conversion | Subtotals bounded by `33 * 511` fit 16 bits; the admitted final interval excludes underflow |
| `sum_layout_fits`, `sub_layout_fits` | `Plan.validate`: fixed group assignment for SUM/SUB | At most nine groups for at most 33 records |

Positive and negative groups are restored before carry propagation. The
authenticated aggregate and fixed layout supply those group values. The
mathematical carry identity preserves value; `no_top_overflow` supplies the
finite-width consequence under the separate subtotal bound. FHE operation
correctness is the component premise. `verify_linear_release` compares the
deterministically normalized ciphertext bytes with the exact requested output.

## Payoff implications

`Economics.operator_gap` verifies the payoff-difference identity, and
`deterrence_sufficient` derives honest payoff superiority from the stated upper
bound on cheating payoff. `challenge_profit_iff` and `participation_profit_iff`
keep marginal challenge costs and ex-ante audit costs separate. The model uses
integer-scaled rational quantities; a common positive denominator preserves the
corresponding payoff comparisons.

`winning_margin` and `coalition_loss` correspond to the constructor constraints
and settlement bookkeeping in `CanonicalBountyFHEDisputeGame.sol`: reward above
disclosure plus other declared costs, and penalty above reward plus the
disclosure cap. `_settleOperatorBond` consumes the reserved penalty and credits
only the specified bounty. The lemmas supply arithmetic implications from
actual-cost bounds. Strategy probabilities, complete coalition accounting and
observed costs are inputs to their economic interpretation. `no_fault_no_profit`
records the zero-reward, positive-cost case.

## Public audit transcripts

`AuditPrivacy.PublicOnly` expresses independence from an additional FHE secret
given public state and independent randomness. `public_transcript_noninterference`
proves preservation through a finite list of such operations;
`public_simulator_exists` constructs the simulator for that composition.

The reviewed source paths are `canonical-protocol.mjs`:
`detectCanonicalFault`/`adjudicateCanonicalLeaf`, and `circuit-executor.rs`:
`execute-canonical`/`leaf`. They use authenticated ciphertexts, public evaluation
material, serialization and digest comparisons. `kms-profile-build.py` restricts
the KMS executor to canonical execution and leaf recomputation, excluding local
decryption entry points. Authorized outputs and failures are part of the supplied
public state. Threshold response security, the response-alphabet entropy bound
and implementation side-channel protection have their respective component
arguments; these two lemmas establish public-operation composition.

## Conditional liveness

`Liveness.Progress` records productive protocol transitions after finite waiting
periods. `State.audit` counts eligible challengers still available; opening a
challenge removes its active author from that count. `State.bisection` additionally
records the remaining depth, and `State.pending` awaits an admitted certificate.

In `VerifiableFHEDisputeGame.sol`, `openChallenge` rejects a spent challenger and
`_reopenAfterLostChallenge` marks the defeated author before reopening.
Authenticated bisection reduces the interval. The task's frozen finite cohort
supplies the initial challenger bound. In `CanonicalBountyFHEDisputeGame.sol`,
the certified decision finalizes an invalid execution or reopens after a false
challenge. Pending admitted disputes retain their state during certificate
outages; later valid certificates can complete settlement.

`progress_decreases` proves that every modeled productive step decreases a
natural-valued measure. `no_infinite_descent` rules out an infinite descent, and
`eventual_finality` combines these facts with eventual productive progress. That
progress premise represents the stated data, relaying, transaction-inclusion
and live-adjudication conditions. The safety model in `DisputeSafety.lean`
continues to admit arbitrary waiting; the liveness model supplies the distinct
conditional termination result.
