import VCFHE.CanonicalExecution

namespace VCFHE.Bisection

/-! `differs lo hi` compares authenticated subtrees for [lo,hi).
`faithful` is the comparison interface under binding, rather than an
injectivity axiom for a finite-output hash function.
-/
def locate (differs : Nat → Nat → Bool) (lo : Nat) : Nat → Nat
  | 0 => lo
  | height + 1 =>
    let mid := lo + 2 ^ height
    if differs lo mid then locate differs lo height else locate differs mid height

theorem isolates_first (different : Nat → Prop) (differs : Nat → Nat → Bool)
    (faithful : ∀ lo hi, differs lo hi = true ↔
      ∃ j, lo ≤ j ∧ j < hi ∧ different j)
    (k : Nat) (first : different k ∧ ∀ j, j < k → ¬ different j)
    (height lo : Nat) (lower : lo ≤ k) (upper : k < lo + 2 ^ height) :
    locate differs lo height = k := by
  induction height generalizing lo with
  | zero => simp only [locate]; simp only [Nat.pow_zero] at upper; omega
  | succ h ih =>
    simp only [locate]
    split
    · rename_i hl
      obtain ⟨j, _, hj, hd⟩ := (faithful lo (lo + 2 ^ h)).mp hl
      have hk : k ≤ j := by
        apply Classical.byContradiction
        intro hn
        exact first.2 j (by omega) hd
      exact ih lo lower (by omega)
    · rename_i hr
      have hmid : lo + 2 ^ h ≤ k := by
        apply Classical.byContradiction
        intro hn
        apply hr
        exact (faithful lo (lo + 2 ^ h)).mpr ⟨k, lower, by omega, first.1⟩
      apply ih (lo + 2 ^ h) hmid
      rw [Nat.pow_succ] at upper
      omega

theorem detection_and_localization {Cipher : Type}
    (step : Nat → Canonical.Trace Cipher → Cipher)
    (dep : Canonical.PrefixDependent step) (height : Nat)
    (reference operator : Canonical.Trace Cipher)
    (valid : Canonical.Valid step (2 ^ height) reference)
    (differs : Nat → Nat → Bool)
    (faithful : ∀ lo hi, differs lo hi = true ↔
      ∃ j, lo ≤ j ∧ j < hi ∧ operator j ≠ reference j)
    (unequal : ∃ i, i < 2 ^ height ∧ operator i ≠ reference i) :
    let k := locate differs 0 height
    k < 2 ^ height ∧ Canonical.FirstDifference operator reference k ∧
      operator k ≠ step k operator := by
  obtain ⟨k, hk, first⟩ := Canonical.first_difference_exists operator reference _ unequal
  have located : locate differs 0 height = k :=
    isolates_first (fun j => operator j ≠ reference j) differs faithful k
      ⟨first.1, fun j hj hn => hn (first.2 j hj)⟩ height 0 (by omega) (by omega)
  simp only [located]
  exact ⟨hk, first,
    Canonical.first_difference_invalid step dep reference operator _ k valid hk first⟩

end VCFHE.Bisection
