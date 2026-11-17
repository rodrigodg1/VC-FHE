import Std

namespace VCFHE.Linear

/- The reduction exposes a nonzero kernel relation; it does not assume
global injectivity of a finite-dimensional commitment. DLR supplies the
computational exclusion of such an efficiently obtained relation. -/
theorem collision_exposes_relation {V G : Type} (P : V → G)
    (subV : V → V → V) (subG : G → G → G) (zeroV : V) (zeroG : G)
    (hom : ∀ a b, P (subV a b) = subG (P a) (P b))
    (cancel : ∀ a b, subV a b = zeroV → a = b)
    (self : ∀ g, subG g g = zeroG)
    (actual expected : V) (sameCommitment : P actual = P expected)
    (different : actual ≠ expected) :
    subV actual expected ≠ zeroV ∧ P (subV actual expected) = zeroG := by
  constructor
  · exact fun h => different (cancel actual expected h)
  · rw [hom, sameCommitment, self]

def aggregate {V : Type} (zero : V) (add : V → V → V) : List V → V
  | [] => zero
  | x :: xs => add x (aggregate zero add xs)

theorem homomorphic_accumulation {V G : Type} (zeroV : V) (zeroG : G)
    (addV : V → V → V) (addG : G → G → G) (P : V → G)
    (hzero : P zeroV = zeroG) (hadd : ∀ a b, P (addV a b) = addG (P a) (P b))
    (weightedInputs : List V) :
    P (aggregate zeroV addV weightedInputs) =
      aggregate zeroG addG (weightedInputs.map P) := by
  induction weightedInputs with
  | nil => exact hzero
  | cons a xs ih => simp only [aggregate, List.map_cons, hadd, ih]

def lift (r s : Int) : Int := if s < 0 then r + s else s
def center (r a : Int) : Int := if 2 * a > r then a - r else a

theorem balanced_lift_exact (r s : Int) (_positive : 0 < r)
    (lower : -r < 2 * s) (upper : 2 * s < r) : center r (lift r s) = s := by
  unfold center lift
  split <;> split <;> omega

theorem balanced_lift_canonical (r s : Int) (positive : 0 < r)
    (lower : -r < 2 * s) (upper : 2 * s < r) :
    0 ≤ lift r s ∧ lift r s < r := by
  unfold lift
  split <;> omega

theorem signed_reduction (r q s : Int) (positive : 0 < r)
    (lower : -r < 2 * s) (upper : 2 * s < r) :
    center r (lift r s) % q = s % q := by
  rw [balanced_lift_exact r s positive lower upper]

/- Once the unwrapped phase lies in its decoding cell, a different message's
cell cannot contain it. Here left/right are the adjacent cell boundaries. -/
theorem strict_decoding_cell (delta m noise : Int) (_positive : 0 < delta)
    (lower : -delta < 2 * noise) (upper : 2 * noise < delta) :
    2 * (delta * m) - delta < 2 * (delta * m + noise) ∧
    2 * (delta * m + noise) < 2 * (delta * m) + delta := by omega

end VCFHE.Linear
