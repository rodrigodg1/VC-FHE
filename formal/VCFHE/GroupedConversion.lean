import Std

namespace VCFHE.GroupedConversion

def value : List Nat → Nat
  | [] => 0
  | d :: ds => d + 4 * value ds

def normalizeValue : List Nat → Nat → Nat
  | [], carry => carry
  | d :: ds, carry => (d + carry) % 4 + 4 * normalizeValue ds ((d + carry) / 4)

theorem carry_conservation (digits : List Nat) (carry : Nat) :
    normalizeValue digits carry = value digits + carry := by
  induction digits generalizing carry with
  | nil => simp [normalizeValue, value]
  | cons d ds ih =>
    simp only [normalizeValue, value, ih, Nat.mul_add]
    have h := Nat.mod_add_div (d + carry) 4
    omega

theorem group_capacity (members degree carry : Nat) (hn : members ≤ 4)
    (hd : degree ≤ 3 * members) (hc : carry ≤ 3) :
    degree + carry ≤ 15 ∧ (degree + carry) / 4 ≤ 3 := by omega

theorem digit_range (total : Nat) : total % 4 ≤ 3 := by omega

theorem group_noise_capacity (members freshCarry : Nat)
    (hn : members ≤ 4) (hc : freshCarry ≤ 1) : members + freshCarry ≤ 5 := by omega

theorem subtotal_fits (n total : Nat) (hn : n ≤ 33) (hm : total ≤ n * 511) :
    total < 65536 := by omega

theorem no_top_overflow (total : Nat) (bound : total < 65536) :
    total % 65536 = total := by omega

theorem interval_subtraction (positive negative : Int)
    (low : 0 ≤ positive - negative) (high : positive - negative ≤ 511) :
    negative ≤ positive ∧ positive - negative < 65536 := by omega

theorem sum_layout_fits (n : Nat) (hn : n ≤ 33) : (n + 3) / 4 ≤ 9 := by omega

theorem sub_layout_fits (n : Nat) (lo : 1 ≤ n) (hi : n ≤ 33) :
    1 + ((n - 1) + 3) / 4 ≤ 9 := by omega

end VCFHE.GroupedConversion
