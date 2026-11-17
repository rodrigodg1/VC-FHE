import VCFHE.Bisection
import VCFHE.Quorum

namespace VCFHE.Dispute

structure Claim where
  auditor : Nat
  leaf : Nat
  candidate : Nat
  deriving DecidableEq, Repr

inductive Phase where
  | auditing
  | challenged (claim : Claim)
  | admitted (claim : Claim)
  | accepted
  | rejected (beneficiary : Option Nat)
  deriving DecidableEq, Repr

structure Rules where
  operatorValid : Nat → Bool
  candidateValid : Claim → Bool
  evidenceValid : Claim → Prop
  timely : Claim → Prop

/-! Evidence-admitted abstraction of the secure canonical game. A certificate
transition denotes a bound, authenticated and sound leaf decision. Its semantic
interface is justified by `Quorum.certified_value_eq`. Intermediate branch
relays preserve the active claim. `timely` excludes a default by that challenger.
The rejection beneficiary records a computational bounty, not a procedural one.
-/
inductive Step (r : Rules) : Phase → Phase → Prop where
  | open (c) : Step r .auditing (.challenged c)
  | relay (c) : Step r (.challenged c) (.challenged c)
  | admit (c) (evidence : r.evidenceValid c) : Step r (.challenged c) (.admitted c)
  | malformedChallenge (c) (malformed : ¬ r.evidenceValid c) :
      Step r (.challenged c) .auditing
  | challengerDefault (c) (late : ¬ r.timely c) :
      Step r (.challenged c) .auditing
  | proceduralReject (c) : Step r (.challenged c) (.rejected none)
  | falseChallenge (c) (valid : r.operatorValid c.leaf = true) :
      Step r (.admitted c) .auditing
  | certifiedReject (c) (invalid : r.operatorValid c.leaf = false)
      (candidateInvalid : r.candidateValid c = false) :
      Step r (.admitted c) (.rejected none)
  | certifiedBounty (c) (invalid : r.operatorValid c.leaf = false)
      (candidateValid : r.candidateValid c = true) :
      Step r (.admitted c) (.rejected (some c.auditor))
  | finalize : Step r .auditing .accepted
  | auditReject : Step r .auditing (.rejected none)
  | wait (s) : Step r s s

inductive Run (r : Rules) : Phase → Phase → Prop where
  | refl (s) : Run r s s
  | cons {a b c} : Step r a b → Run r b c → Run r a c

def Protected (c : Claim) (s : Phase) : Prop :=
  s = .challenged c ∨ s = .admitted c ∨ ∃ b, s = .rejected b

theorem protected_step (r : Rules) (c : Claim)
    (invalid : r.operatorValid c.leaf = false) (evidence : r.evidenceValid c)
    (timely : r.timely c)
    (a b : Phase) (hprotected : Protected c a) (step : Step r a b) :
    Protected c b := by
  cases step <;> simp_all [Protected]

theorem protected_run (r : Rules) (c : Claim)
    (invalid : r.operatorValid c.leaf = false) (evidence : r.evidenceValid c)
    (timely : r.timely c)
    (a b : Phase) (hprotected : Protected c a) (run : Run r a b) :
    Protected c b := by
  induction run with
  | refl => exact hprotected
  | cons step rest ih =>
    exact ih (protected_step r c invalid evidence timely _ _ hprotected step)

theorem challenge_blocks_acceptance (r : Rules) (c : Claim)
    (invalid : r.operatorValid c.leaf = false) (evidence : r.evidenceValid c)
    (timely : r.timely c) :
    ¬ Run r (.challenged c) .accepted := by
  intro run
  have hp := protected_run r c invalid evidence timely _ _ (Or.inl rfl) run
  simp [Protected] at hp

theorem admitted_outage_preserves_pending (r : Rules) (c : Claim)
    (b : Phase) (step : Step r (.admitted c) b)
    (noDecision : b ≠ .auditing ∧ ∀ x, b ≠ .rejected x) : b = .admitted c := by
  cases step <;> simp_all

theorem rejected_stays_rejected (r : Rules) (beneficiary : Option Nat)
    (b : Phase) (run : Run r (.rejected beneficiary) b) :
    b = .rejected beneficiary := by
  suffices h : ∀ a b, Run r a b → a = .rejected beneficiary →
      b = .rejected beneficiary from h _ _ run rfl
  intro a b execution
  induction execution with
  | refl => exact fun h => h
  | cons step rest ih =>
    intro h
    cases h
    cases step
    exact ih rfl

theorem bounty_requires_both_results (r : Rules) (a : Phase) (beneficiary : Nat)
    (step : Step r a (.rejected (some beneficiary)))
    (notFinal : a ≠ .rejected (some beneficiary)) :
    ∃ c, a = .admitted c ∧ c.auditor = beneficiary ∧
      r.operatorValid c.leaf = false ∧ r.candidateValid c = true := by
  cases step with
  | certifiedBounty c invalid valid => exact ⟨c, rfl, rfl, invalid, valid⟩
  | wait => exact False.elim (notFinal rfl)

theorem admitted_bounty_settlement (r : Rules) (c : Claim)
    (invalid : r.operatorValid c.leaf = false)
    (valid : r.candidateValid c = true) (evidence : r.evidenceValid c) :
    Run r (.challenged c) (.rejected (some c.auditor)) :=
  .cons (.admit c evidence) (.cons (.certifiedBounty c invalid valid) (.refl _))

/-! Coverage is an execution witness: the invalid first-difference claim
became active and its subsequent transitions obeyed its deadlines. The suffix
is part of the observed execution, not an assumption about its outcome.
-/
def Covered {Cipher : Type} (r : Rules) (n : Nat)
    (operator reference : Canonical.Trace Cipher) (final : Phase) : Prop :=
  ∀ k, k < n → Canonical.FirstDifference operator reference k →
    ∃ c, c.leaf = k ∧ r.evidenceValid c ∧ r.timely c ∧ Run r (.challenged c) final

theorem conditional_trace_soundness {Cipher : Type}
    (eval : Nat → Canonical.Trace Cipher → Cipher)
    (dep : Canonical.PrefixDependent eval) (n : Nat)
    (reference operator : Canonical.Trace Cipher)
    (referenceValid : Canonical.Valid eval n reference) (r : Rules)
    (leafMeaning : ∀ k, k < n →
      (r.operatorValid k = true ↔ operator k = eval k operator))
    (coverage : Covered r n operator reference .accepted) :
    ∀ i, i < n → operator i = reference i := by
  rcases Canonical.detection eval dep n reference operator referenceValid with same | diff
  · exact same
  · obtain ⟨k, hk, first, invalid⟩ := diff
    obtain ⟨c, leaf, evidence, timely, suffix⟩ := coverage k hk first
    have hv : r.operatorValid c.leaf = false := by
      rw [leaf]
      cases h : r.operatorValid k with
      | false => rfl
      | true => exact False.elim (invalid ((leafMeaning k hk).mp h))
    exact False.elim (challenge_blocks_acceptance r c hv evidence timely suffix)

end VCFHE.Dispute
