// Monetary inputs must be supplied in the same unit. This calculator checks
// consistency, not whether deployment cost estimates or detection rates hold.
import { readFileSync } from 'node:fs';

const MAX_UINT256 = (1n << 256n) - 1n;
function uint(value, name) {
  if (typeof value !== 'bigint' && (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)))
    throw new Error(`${name} must be an unsigned decimal string or bigint`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > MAX_UINT256) throw new Error(`${name} exceeds uint256`);
  return parsed;
}

export function calibrateBountyEconomics(config) {
  const { maxTraceLeaves } = config;
  if (!Number.isSafeInteger(maxTraceLeaves) || maxTraceLeaves < 1 || maxTraceLeaves > 2 ** 31 ||
      !Number.isInteger(Math.log2(maxTraceLeaves))) throw new Error('maxTraceLeaves must be a uint32 power of two');
  const base = uint(config.disclosureBaseWei, 'disclosureBaseWei');
  const perLeaf = uint(config.disclosurePerLeafWei, 'disclosurePerLeafWei');
  const cost = uint(config.challengeCostBudgetWei, 'challengeCostBudgetWei');
  const margin = uint(config.challengerMarginWei, 'challengerMarginWei');
  const loss = uint(config.operatorLossFloorWei, 'operatorLossFloorWei');
  if (cost === 0n || margin === 0n || loss === 0n) throw new Error('cost budget and margins must be positive');
  const fee = base + perLeaf * BigInt(maxTraceLeaves);
  const reward = fee + cost + margin;
  const penalty = reward + fee + loss;
  if (penalty > MAX_UINT256) throw new Error('calibration exceeds uint256');
  return Object.freeze({
    revision: 'bounded-cost-v1', maxTraceLeaves,
    maxDisclosureFeeWei: String(fee), challengeCostBudgetWei: String(cost),
    challengerMarginWei: String(margin), operatorLossFloorWei: String(loss),
    bountyWei: String(reward), operatorPenaltyWei: String(penalty),
    extraConstructorArgs: Object.freeze([String(penalty), String(reward), maxTraceLeaves, String(cost)])
  });
}

// These declared budgets exercise the checks. They are not empirical prices.
export const BOUNTY_TEST_COSTS = Object.freeze(JSON.parse(
  readFileSync(new URL('./bounty-economics.json', import.meta.url), 'utf8')));
export const BOUNTY_TEST_ECONOMICS = calibrateBountyEconomics(BOUNTY_TEST_COSTS);
