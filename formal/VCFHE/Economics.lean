import Std

namespace VCFHE.Economics

/- Scale all rational probabilities by the common positive denominator d.
The payoff identity itself is an integer polynomial identity. -/
theorem operator_gap (d p reward benefit loss honestCost cheatCost : Int) :
    (d * reward - d * honestCost) -
      ((d - p) * (reward + benefit) - p * loss - d * cheatCost) =
    p * (loss + reward) - (d - p) * benefit - d * (honestCost - cheatCost) := by
  simp only [Int.sub_mul, Int.mul_add, Int.mul_sub]
  omega

theorem deterrence_sufficient (d p reward benefit loss honestCost cheatCost actualCheat : Int)
    (cheatBound : actualCheat ≤ (d - p) * (reward + benefit) - p * loss - d * cheatCost)
    (condition : p * (loss + reward) > (d - p) * benefit + d * (honestCost - cheatCost)) :
    d * reward - d * honestCost > actualCheat := by
  have h := operator_gap d p reward benefit loss honestCost cheatCost
  omega

theorem challenge_profit_iff (pReward pBond reward cost bond denominator : Int) :
    0 < pReward * reward - denominator * cost - pBond * bond ↔
    pReward * reward > denominator * cost + pBond * bond := by omega

theorem participation_profit_iff (pWin reward monitor other losses denominator : Int) :
    0 < pWin * reward - denominator * (monitor + other + losses) ↔
    pWin * reward > denominator * (monitor + other + losses) := by omega

theorem winning_margin (reward feeLimit costLimit fee cost : Int)
    (deployed : reward > feeLimit + costLimit)
    (feeBound : fee ≤ feeLimit) (costBound : cost ≤ costLimit) :
    reward - fee - cost > 0 := by omega

theorem coalition_loss (penalty reward feeLimit fee : Int)
    (deployed : penalty > reward + feeLimit) (feeBound : fee ≤ feeLimit) :
    penalty - reward - fee > 0 := by omega

theorem no_fault_no_profit (cost : Int) (positive : cost > 0) :
    0 - cost < 0 := by omega

end VCFHE.Economics
