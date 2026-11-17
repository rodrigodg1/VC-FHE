import VCFHE.Composition

namespace VCFHE.EndToEnd

/-! Each outcome records one accepted nonlinear task and one result recovery.
The component predicates below expose the assumptions supplied when the
corresponding failure events are absent. They do not assume plaintext equality.
-/
structure Execution where
  eval : Nat → Canonical.Trace Nat → Nat
  last : Nat
  reference : Canonical.Trace Nat
  operator : Canonical.Trace Nat
  rules : Dispute.Rules
  policy : Release.Config
  state : Release.State
  request : Release.Request
  q : Nat
  f : Nat
  faulty : Fin q → Bool
  decrypt : Nat → Nat
  intended : Nat
  plaintext : Nat

structure BindingOK (t : Execution) : Prop where
  dependence : Canonical.PrefixDependent t.eval
  referenceValid : Canonical.Valid t.eval (t.last + 1) t.reference
  initialBounds : ∀ record, t.policy.initialSpent record ≤ t.policy.limit record
  policyRun : Release.Reachable t.policy t.state
  acceptedBinding : t.policy.acceptedOutput (t.policy.terms t.request.consent).task =
    some (t.operator t.last)

def CertificateOK (t : Execution) : Prop :=
  ∀ k, k < t.last + 1 →
    (t.rules.operatorValid k = true ↔ t.operator k = t.eval k t.operator)

structure KMSOK (t : Execution) : Prop where
  corruption : Quorum.faultyCount t.q t.faulty ≤ t.f
  threshold : t.f < t.q
  honestDuty : ∀ i, t.faulty i = false → t.request ∈ t.state.reserved
  outputValidation : t.request ∈ t.state.reserved → Release.OutputBound t.policy t.request
  responseCorrect : t.plaintext = t.decrypt t.request.output

theorem nonlinear_plaintext_error_bound {Outcome : Type}
    (outcomes : List Outcome) (weight : Outcome → Nat) (execution : Outcome → Execution)
    (coverage binding certificate fhe kms : Outcome → Prop)
    (bindingInterface : ∀ x, ¬ binding x → BindingOK (execution x))
    (certificateInterface : ∀ x, ¬ binding x → ¬ certificate x → CertificateOK (execution x))
    (coverageInterface : ∀ x, coverage x → ¬ binding x → ¬ certificate x →
      Dispute.Covered (execution x).rules ((execution x).last + 1)
        (execution x).operator (execution x).reference .accepted)
    (fheInterface : ∀ x, ¬ fhe x →
      (execution x).decrypt ((execution x).reference (execution x).last) = (execution x).intended)
    (kmsInterface : ∀ x, ¬ binding x → ¬ kms x → KMSOK (execution x)) :
    Composition.mass outcomes weight (fun x => (execution x).plaintext ≠ (execution x).intended) ≤
      Composition.mass outcomes weight (fun x => ¬ coverage x) +
      Composition.mass outcomes weight binding + Composition.mass outcomes weight certificate +
      Composition.mass outcomes weight fhe + Composition.mass outcomes weight kms := by
  apply Composition.five_event_error_bound
  intro x hg hb hc hf hk
  let t := execution x
  have b := bindingInterface x hb
  have k := kmsInterface x hb hk
  have correct := Composition.released_plaintext_correct
    t.eval b.dependence t.last t.reference t.operator b.referenceValid t.rules
    (certificateInterface x hb hc) (coverageInterface x hg hb hc)
    t.policy t.state t.request b.initialBounds b.policyRun t.q t.f t.faulty
    k.corruption k.threshold k.honestDuty k.outputValidation b.acceptedBinding
    t.decrypt t.intended t.plaintext (fheInterface x hf) k.responseCorrect
  exact fun incorrect => incorrect correct.2

end VCFHE.EndToEnd
