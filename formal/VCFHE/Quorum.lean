import Std

/-! A certificate is indexed by its distinct, authenticated signers. The
corruption bound counts indices in that certificate, not unauthenticated bytes.
-/
namespace VCFHE.Quorum

def faultyCount : (n : Nat) → (Fin n → Bool) → Nat
  | 0, _ => 0
  | n + 1, faulty => (if faulty 0 then 1 else 0) +
      faultyCount n (fun i => faulty i.succ)

theorem count_le_size (n : Nat) (flags : Fin n → Bool) : faultyCount n flags ≤ n := by
  induction n with
  | zero => simp [faultyCount]
  | succ n ih =>
    have h := ih (fun i => flags i.succ)
    simp only [faultyCount]
    split <;> omega

theorem full_count_all_true (n : Nat) (flags : Fin n → Bool)
    (full : faultyCount n flags = n) : ∀ i, flags i = true := by
  induction n with
  | zero => intro i; exact Fin.elim0 i
  | succ n ih =>
    have bound := count_le_size n (fun i => flags i.succ)
    have head : flags 0 = true := by
      cases h : flags 0 with
      | false => simp [faultyCount, h] at full; omega
      | true => rfl
    have tail : faultyCount n (fun i => flags i.succ) = n := by
      simp only [faultyCount, head, ↓reduceIte] at full
      omega
    intro i
    exact Fin.cases head (fun j => ih _ tail j) i

theorem all_faulty_count (n : Nat) (faulty : Fin n → Bool)
    (allFaulty : ∀ i, faulty i = true) : faultyCount n faulty = n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [faultyCount]
    rw [allFaulty 0, ih _ (fun i => allFaulty i.succ)]
    simp only [↓reduceIte]
    omega

theorem honest_signer_exists (q f : Nat) (faulty : Fin q → Bool)
    (bound : faultyCount q faulty ≤ f) (threshold : f < q) :
    ∃ i, faulty i = false := by
  apply Classical.byContradiction
  intro none
  have allFaulty : ∀ i, faulty i = true := by
    intro i
    cases h : faulty i with
    | false => exact False.elim (none ⟨i, h⟩)
    | true => rfl
  have h := all_faulty_count q faulty allFaulty
  omega

theorem certified_value_eq {Value : Type} (q f : Nat) (faulty : Fin q → Bool)
    (bound : faultyCount q faulty ≤ f) (threshold : f < q)
    (certified expected : Value)
    (honestRule : ∀ i, faulty i = false → certified = expected) :
    certified = expected := by
  obtain ⟨i, hi⟩ := honest_signer_exists q f faulty bound threshold
  exact honestRule i hi

theorem threshold_feasible (n f q : Nat) (safety : f < q)
    (availability : q ≤ n - f) : 2 * f < n := by omega

end VCFHE.Quorum
