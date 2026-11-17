import Std

/-! Deterministic execution of a fixed, authenticated acyclic program.
`step i t` uses only outputs preceding instruction `i`; authenticated inputs,
constants, the opcode and the evaluator profile are fixed in `step`.
-/
namespace VCFHE.Canonical

abbrev Trace (Cipher : Type) := Nat → Cipher

def PrefixDependent {Cipher : Type} (step : Nat → Trace Cipher → Cipher) : Prop :=
  ∀ i a b, (∀ j, j < i → a j = b j) → step i a = step i b

def Valid {Cipher : Type} (step : Nat → Trace Cipher → Cipher)
    (n : Nat) (trace : Trace Cipher) : Prop :=
  ∀ i, i < n → trace i = step i trace

def FirstDifference {Cipher : Type} (a b : Trace Cipher) (k : Nat) : Prop :=
  a k ≠ b k ∧ ∀ j, j < k → a j = b j

theorem first_difference_exists {Cipher : Type} (a b : Trace Cipher) (n : Nat)
    (different : ∃ i, i < n ∧ a i ≠ b i) :
    ∃ k, k < n ∧ FirstDifference a b k := by
  induction n with
  | zero => obtain ⟨i, hi, _⟩ := different; omega
  | succ n ih =>
    by_cases earlier : ∃ i, i < n ∧ a i ≠ b i
    · obtain ⟨k, hk, hf⟩ := ih earlier
      exact ⟨k, by omega, hf⟩
    · have agrees : ∀ i, i < n → a i = b i := by
        intro i hi
        apply Classical.byContradiction
        intro hn
        exact earlier ⟨i, hi, hn⟩
      obtain ⟨i, hi, hn⟩ := different
      have hin : i = n := by
        apply Classical.byContradiction
        intro hne
        exact hn (agrees i (by omega))
      subst i
      exact ⟨n, by omega, hn, agrees⟩

theorem first_difference_invalid {Cipher : Type}
    (step : Nat → Trace Cipher → Cipher) (dep : PrefixDependent step)
    (reference operator : Trace Cipher) (n k : Nat)
    (referenceValid : Valid step n reference) (hk : k < n)
    (first : FirstDifference operator reference k) :
    operator k ≠ step k operator := by
  intro validAtK
  apply first.1
  calc
    operator k = step k operator := validAtK
    _ = step k reference := dep k operator reference first.2
    _ = reference k := (referenceValid k hk).symm

theorem valid_traces_agree {Cipher : Type}
    (step : Nat → Trace Cipher → Cipher) (dep : PrefixDependent step)
    (n : Nat) (a b : Trace Cipher) (ha : Valid step n a) (hb : Valid step n b) :
    ∀ i, i < n → a i = b i := by
  intro i hi
  apply Classical.byContradiction
  intro hn
  obtain ⟨k, hk, hf⟩ := first_difference_exists a b n ⟨i, hi, hn⟩
  exact first_difference_invalid step dep b a n k hb hk hf (ha k hk)

theorem detection {Cipher : Type} (step : Nat → Trace Cipher → Cipher)
    (dep : PrefixDependent step) (n : Nat) (reference operator : Trace Cipher)
    (referenceValid : Valid step n reference) :
    (∀ i, i < n → operator i = reference i) ∨
    ∃ k, k < n ∧ FirstDifference operator reference k ∧
      operator k ≠ step k operator := by
  classical
  by_cases same : ∀ i, i < n → operator i = reference i
  · exact Or.inl same
  · have differs : ∃ i, i < n ∧ operator i ≠ reference i := by
      apply Classical.byContradiction
      intro none
      apply same
      intro i hi
      apply Classical.byContradiction
      intro hn
      exact none ⟨i, hi, hn⟩
    obtain ⟨k, hk, hf⟩ := first_difference_exists operator reference n differs
    exact Or.inr ⟨k, hk, hf,
      first_difference_invalid step dep reference operator n k referenceValid hk hf⟩

theorem terminal_agreement {Cipher : Type} (step : Nat → Trace Cipher → Cipher)
    (dep : PrefixDependent step) (last : Nat) (a b : Trace Cipher)
    (ha : Valid step (last + 1) a) (hb : Valid step (last + 1) b) :
    a last = b last :=
  valid_traces_agree step dep (last + 1) a b ha hb last (by omega)

end VCFHE.Canonical
