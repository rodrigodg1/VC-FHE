import VCFHE.DisputeSafety
import VCFHE.ReleasePolicy

namespace VCFHE.Composition

/-! Ciphertext and output identifiers are represented by Nat tokens here.
Their correspondence to serialized ciphertexts is supplied by authenticated
binding and delivery. `fheCorrect` and `kmsCorrect` state the task-level
correctness interfaces; the cryptographic constructions implement these.
-/
theorem released_plaintext_correct
    (eval : Nat → Canonical.Trace Nat → Nat) (dep : Canonical.PrefixDependent eval)
    (last : Nat) (reference operator : Canonical.Trace Nat)
    (referenceValid : Canonical.Valid eval (last + 1) reference)
    (rules : Dispute.Rules)
    (leafMeaning : ∀ k, k < last + 1 →
      (rules.operatorValid k = true ↔ operator k = eval k operator))
    (coverage : Dispute.Covered rules (last + 1) operator reference .accepted)
    (policy : Release.Config) (state : Release.State) (request : Release.Request)
    (initialBounds : ∀ record, policy.initialSpent record ≤ policy.limit record)
    (policyRun : Release.Reachable policy state)
    (q f : Nat) (faulty : Fin q → Bool)
    (corruption : Quorum.faultyCount q faulty ≤ f) (threshold : f < q)
    (honestDuty : ∀ i, faulty i = false → request ∈ state.reserved)
    (outputValidation : request ∈ state.reserved → Release.OutputBound policy request)
    (acceptedBinding : policy.acceptedOutput (policy.terms request.consent).task =
      some (operator last))
    (decrypt : Nat → Nat) (intended plaintext : Nat)
    (fheCorrect : decrypt (reference last) = intended)
    (kmsCorrect : plaintext = decrypt request.output) :
    Release.Authorized policy state request ∧ plaintext = intended := by
  obtain ⟨auth, outputBound⟩ := Release.threshold_release_bound policy state initialBounds
    policyRun request q f faulty corruption threshold honestDuty outputValidation
  have same := Dispute.conditional_trace_soundness eval dep (last + 1)
    reference operator referenceValid rules leafMeaning coverage last (by omega)
  have requestBinding : request.output = operator last := by
    have h := outputBound.1
    rw [acceptedBinding] at h
    exact (Option.some.inj h).symm
  refine ⟨auth, ?_⟩
  calc
    plaintext = decrypt request.output := kmsCorrect
    _ = decrypt (operator last) := congrArg decrypt requestBinding
    _ = decrypt (reference last) := congrArg decrypt same
    _ = intended := fheCorrect

/-! Finite weighted event algebra. Natural weights represent arbitrary rational
probabilities after division by one common positive total weight. Neither
disjointness nor probabilistic independence is required.
-/
noncomputable def mass {Outcome : Type} (outcomes : List Outcome)
    (weight : Outcome → Nat) (event : Outcome → Prop) : Nat := by
  classical
  exact (outcomes.map fun x => if event x then weight x else 0).sum

theorem failure_containment {Outcome : Type}
    (error coverage binding certificate fhe kms : Outcome → Prop)
    (correct : ∀ x, coverage x → ¬ binding x → ¬ certificate x →
      ¬ fhe x → ¬ kms x → ¬ error x) (x : Outcome) (bad : error x) :
    ¬ coverage x ∨ binding x ∨ certificate x ∨ fhe x ∨ kms x := by
  by_cases hg : coverage x
  · by_cases hb : binding x
    · exact Or.inr (Or.inl hb)
    · by_cases hc : certificate x
      · exact Or.inr (Or.inr (Or.inl hc))
      · by_cases hf : fhe x
        · exact Or.inr (Or.inr (Or.inr (Or.inl hf)))
        · by_cases hk : kms x
          · exact Or.inr (Or.inr (Or.inr (Or.inr hk)))
          · exact False.elim (correct x hg hb hc hf hk bad)
  · exact Or.inl hg

theorem weighted_union_bound {Outcome : Type}
    (outcomes : List Outcome) (weight : Outcome → Nat)
    (error a b c d e : Outcome → Prop)
    (contained : ∀ x, error x → a x ∨ b x ∨ c x ∨ d x ∨ e x) :
    mass outcomes weight error ≤ mass outcomes weight a + mass outcomes weight b +
      mass outcomes weight c + mass outcomes weight d + mass outcomes weight e := by
  classical
  have pointwise : ∀ x,
      (if error x then weight x else 0) ≤
      (if a x then weight x else 0) + (if b x then weight x else 0) +
      (if c x then weight x else 0) + (if d x then weight x else 0) +
      (if e x then weight x else 0) := by
    intro x
    by_cases hx : error x
    · have cover := contained x hx
      rcases cover with ha | hb | hc | hd | he <;> simp_all <;> omega
    · simp [hx]
  induction outcomes with
  | nil => simp [mass]
  | cons x xs ih =>
    have h := pointwise x
    simp only [mass, List.map_cons, List.sum_cons] at *
    omega

theorem five_event_error_bound {Outcome : Type}
    (outcomes : List Outcome) (weight : Outcome → Nat)
    (error coverage binding certificate fhe kms : Outcome → Prop)
    (correct : ∀ x, coverage x → ¬ binding x → ¬ certificate x →
      ¬ fhe x → ¬ kms x → ¬ error x) :
    mass outcomes weight error ≤ mass outcomes weight (fun x => ¬ coverage x) +
      mass outcomes weight binding + mass outcomes weight certificate +
      mass outcomes weight fhe + mass outcomes weight kms := by
  apply weighted_union_bound
  exact failure_containment error coverage binding certificate fhe kms correct

end VCFHE.Composition
