import VCFHE.EndToEnd

namespace VCFHE.Witnesses

/-! Concrete inhabitation and guard-necessity witnesses. These are proved
statements, not sampled executions. Modified-guard examples concern the
modified model named in each theorem.
-/
def exampleConfig : Release.Config where
  terms := fun _ => ⟨3, 4, [7], 6, 123⟩
  owner := fun _ => 9
  limit := fun _ => 2
  initialSpent := fun _ => 0
  acceptedOutput := fun _ => some 5
  chainFinality := fun r => r.output = 5
  recipientSigned := fun _ => True
  deliveryValid := fun _ => True

def exampleRequest : Release.Request := ⟨10, 1, 2, 5, 6, 7, 8, 9, 10⟩

def approvedState (c : Release.Config) : Release.State :=
  Release.approveExact (Release.approveConsent (Release.initial c) 10 9)
    exampleRequest 9

theorem approved_state_reachable (c : Release.Config) :
    Release.Reachable c (approvedState c) := by
  exact .next (.next .init (.consent _ 10 9)) (.exact _ exampleRequest 9)

theorem reservation_guard_inhabited :
    Release.Guard exampleConfig (approvedState exampleConfig) exampleRequest := by
  simp [Release.Guard, Release.Authorized, approvedState, Release.approveExact,
    Release.approveConsent, Release.initial, exampleConfig, exampleRequest]

theorem authorized_reservation_exists :
    ∃ s, Release.Reachable exampleConfig s ∧
      exampleRequest ∈ s.reserved ∧ s.spent 7 = 1 ∧
      Release.Authorized exampleConfig s exampleRequest := by
  let s := Release.reserve exampleConfig (approvedState exampleConfig) exampleRequest
  have run : Release.Reachable exampleConfig s :=
    .next (approved_state_reachable _) (.reservation _ _ reservation_guard_inhabited)
  have inv := Release.reachable_invariant exampleConfig (by intro r; exact Nat.zero_le _) s run
  exact ⟨s, run, by simp [s, Release.reserve], rfl,
    inv.authorization exampleRequest (by simp [s, Release.reserve])⟩

def exampleRules : Dispute.Rules where
  operatorValid := fun _ => false
  candidateValid := fun _ => true
  evidenceValid := fun _ => True
  timely := fun _ => True

def exampleClaim : Dispute.Claim := ⟨1, 0, 0⟩

theorem covered_invalid_execution_rejects :
    Dispute.Run exampleRules (.challenged exampleClaim) (.rejected (some 1)) ∧
    ¬ Dispute.Run exampleRules (.challenged exampleClaim) .accepted := by
  exact ⟨Dispute.admitted_bounty_settlement _ _ rfl rfl trivial,
    Dispute.challenge_blocks_acceptance _ _ rfl trivial trivial⟩

theorem uncovered_acceptance_witness :
    Dispute.Run exampleRules .auditing .accepted ∧
    ¬ Dispute.Covered exampleRules 1 (fun _ => (1 : Nat)) (fun _ => 0) .accepted := by
  refine ⟨.cons .finalize (.refl _), ?_⟩
  intro coverage
  have first : Canonical.FirstDifference (fun _ => (1 : Nat)) (fun _ => 0) 0 := by
    constructor
    · decide
    · intro j hj; omega
  obtain ⟨c, _, evidence, timely, run⟩ := coverage 0 (by omega) first
  exact Dispute.challenge_blocks_acceptance _ c rfl evidence timely run

theorem corruption_bound_is_necessary :
    Quorum.faultyCount 1 (fun _ => true) = 1 ∧
    (∀ i : Fin 1, (fun _ : Fin 1 => true) i = false → (1 : Nat) = 0) ∧
    (1 : Nat) ≠ 0 := by
  simp [Quorum.faultyCount]

theorem budget_guard_is_necessary :
    let c := { exampleConfig with initialSpent := fun _ => 2 }
    let s := approvedState c
    (Release.reserve c s exampleRequest).spent 7 > c.limit 7 ∧
    ¬ Release.Guard c s exampleRequest := by
  simp [Release.reserve, Release.Guard, approvedState, exampleConfig, exampleRequest,
    Release.approveExact, Release.approveConsent, Release.initial]

theorem changed_recipient_requires_authorization :
    let changed := { exampleRequest with recipient := 99 }
    ¬ Release.Guard exampleConfig (approvedState exampleConfig) changed := by
  simp [Release.Guard, Release.Authorized, exampleConfig, exampleRequest]

def completeExecution : EndToEnd.Execution where
  eval := fun _ _ => 5
  last := 0
  reference := fun _ => 5
  operator := fun _ => 5
  rules := { exampleRules with operatorValid := fun _ => true }
  policy := exampleConfig
  state := Release.reserve exampleConfig (approvedState exampleConfig) exampleRequest
  request := exampleRequest
  q := 1
  f := 0
  faulty := fun _ => false
  decrypt := id
  intended := 5
  plaintext := 5

theorem end_to_end_premises_inhabited :
    EndToEnd.BindingOK completeExecution ∧ EndToEnd.CertificateOK completeExecution ∧
    EndToEnd.KMSOK completeExecution ∧
    Dispute.Covered completeExecution.rules 1 completeExecution.operator
      completeExecution.reference .accepted ∧
    completeExecution.decrypt (completeExecution.reference completeExecution.last) =
      completeExecution.intended := by
  refine ⟨?_, ?_, ?_, ?_, rfl⟩
  · constructor
    · intro i a b same; rfl
    · intro i hi; rfl
    · intro record; exact Nat.zero_le _
    · exact .next (approved_state_reachable _)
        (.reservation _ _ reservation_guard_inhabited)
    · rfl
  · intro i hi; simp [completeExecution]
  · constructor
    · simp [completeExecution, Quorum.faultyCount]
    · decide
    · intro i honest; simp [completeExecution, Release.reserve]
    · intro reserved; constructor <;> simp [Release.OutputBound, completeExecution,
        exampleConfig, exampleRequest]
    · rfl
  · intro k hk first
    exact False.elim (first.1 rfl)

end VCFHE.Witnesses
