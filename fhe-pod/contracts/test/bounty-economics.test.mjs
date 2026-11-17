import test from 'node:test';
import assert from 'node:assert/strict';
import { calibrateBountyEconomics, BOUNTY_TEST_COSTS, BOUNTY_TEST_ECONOMICS } from '../../scripts/bounty-economics.mjs';

test('test profile covers publication and the declared costs throughout its admitted trace range', () => {
  const c = BOUNTY_TEST_ECONOMICS;
  assert.equal(c.bountyWei, '1544000000000000000');
  assert.equal(c.operatorPenaltyWei, '3338000000000000000');
  for (let leaves = 1; leaves <= c.maxTraceLeaves; leaves *= 2) {
    const fee = BigInt(BOUNTY_TEST_COSTS.disclosureBaseWei) + BigInt(leaves) * BigInt(BOUNTY_TEST_COSTS.disclosurePerLeafWei);
    assert.ok(BigInt(c.bountyWei) - fee - BigInt(c.challengeCostBudgetWei) >= BigInt(c.challengerMarginWei));
    assert.ok(BigInt(c.operatorPenaltyWei) - BigInt(c.bountyWei) - fee >= BigInt(c.operatorLossFloorWei));
  }
});

test('calibration rejects absent costs, zero margins, unsafe numbers and overflow', () => {
  for (const change of [{maxTraceLeaves:0}, {maxTraceLeaves:3}, {maxTraceLeaves:2 ** 32},
    {challengeCostBudgetWei:undefined}, {challengeCostBudgetWei:'0'}, {challengerMarginWei:'0'},
    {operatorLossFloorWei:'0'}, {disclosureBaseWei:-1n}, {disclosurePerLeafWei:0.002},
    {challengeCostBudgetWei:1e18}, {challengeCostBudgetWei:String((1n<<256n)-1n)}])
    assert.throws(() => calibrateBountyEconomics({...BOUNTY_TEST_COSTS,...change}));
});

test('bounds scale jointly without treating returned collateral as income', () => {
  for (const leaves of [1,128,512,1024]) {
    const c=calibrateBountyEconomics({...BOUNTY_TEST_COSTS,maxTraceLeaves:leaves});
    const fee=BigInt(c.maxDisclosureFeeWei), reward=BigInt(c.bountyWei), penalty=BigInt(c.operatorPenaltyWei);
    assert.equal(reward-fee-BigInt(c.challengeCostBudgetWei),BigInt(c.challengerMarginWei));
    assert.equal(penalty-reward-fee,BigInt(c.operatorLossFloorWei));
  }
});
