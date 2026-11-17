import Std

namespace VCFHE.Liveness

/- Productive transitions compress finite waits and authenticated relays.
Fair, timely progress supplies such transitions; certificate outages are not
declared live. Remaining counts exclude the currently active challenger. -/
inductive State where
  | audit (remaining : Nat)
  | bisection (remaining depth : Nat)
  | pending (remaining : Nat)
  | final
  deriving DecidableEq

def rank (height : Nat) : State → Nat
  | .audit n => n * (height + 3) + 1
  | .bisection n depth => n * (height + 3) + depth + 3
  | .pending n => n * (height + 3) + 2
  | .final => 0

inductive Progress (height : Nat) : State → State → Prop where
  | challenge (n) : Progress height (.audit (n + 1)) (.bisection n height)
  | bisect (n depth) : Progress height (.bisection n (depth + 1)) (.bisection n depth)
  | admit (n) : Progress height (.bisection n 0) (.pending n)
  | falseChallenge (n) : Progress height (.pending n) (.audit n)
  | malformed (n depth) : Progress height (.bisection n depth) (.audit n)
  | certifiedEnd (n) : Progress height (.pending n) .final
  | proceduralEnd (n depth) : Progress height (.bisection n depth) .final
  | finalize (n) : Progress height (.audit n) .final

theorem progress_decreases (height : Nat) (a b : State)
    (step : Progress height a b) : rank height b < rank height a := by
  cases step <;> simp only [rank, Nat.add_mul, Nat.one_mul] <;> omega

theorem no_infinite_descent (f : Nat → Nat) : ¬ (∀ i, f (i + 1) < f i) := by
  intro decreases
  have bound : ∀ i, f i + i ≤ f 0 := by
    intro i
    induction i with
    | zero => omega
    | succ i ih => have h := decreases i; omega
  have h := bound (f 0 + 1)
  omega

theorem eventual_finality (height : Nat) (execution : Nat → State)
    (live : ∀ i, execution i ≠ .final → Progress height (execution i) (execution (i + 1))) :
    ∃ i, execution i = .final := by
  apply Classical.byContradiction
  intro never
  apply no_infinite_descent (fun i => rank height (execution i))
  intro i
  have nonfinal : execution i ≠ .final := fun h => never ⟨i, h⟩
  exact progress_decreases height _ _ (live i nonfinal)

end VCFHE.Liveness
