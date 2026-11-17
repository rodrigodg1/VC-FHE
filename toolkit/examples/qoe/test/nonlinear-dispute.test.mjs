/**
 * On-chain verification tests for the NON-LINEAR QoE examples: for each
 * real-data workload the production pipeline (fixture regeneration ->
 * micro-ISA lowering -> Hardhat dispute game) must accept the honest node and
 * slash the dishonest operator through challenge -> bisection -> objective
 * leaf resolution on-chain.
 *
 * The real-TFHE workload computations themselves are covered by
 * `npm run fhe:correctness` (tfhe-rs); set SKIP_FHE_CORRECTNESS=1 to avoid
 * re-running that suite inside this test (the on-chain dispute still runs).
 *
 * Run: npm run test:nonlinear      (several minutes: two full dispute games)
 */
import test from "node:test";
import assert from "node:assert/strict";
import { runWorkload, WORKLOADS } from "../nonlinear/run-dispute.mjs";

for (const workloadId of Object.keys(WORKLOADS)) {
  test(`${workloadId}: honest accepted, dishonest slashed on-chain (Hardhat)`, async () => {
    const { row, checks } = await runWorkload(workloadId, {
      skipFheCorrectness: process.env.SKIP_FHE_CORRECTNESS !== "0",
    });
    assert.equal(checks.honestAccepted, true, "honest node accepted optimistically");
    assert.equal(checks.dishonestSlashed, true, "dishonest node decided for the challenger");
    assert.equal(checks.operatorLeafInvalid, true, "objective verifier rejected the manipulated leaf");
    assert.equal(checks.challengerLeafValid, true, "objective verifier confirmed the challenger leaf");
    assert.equal(checks.operatorStakeSlashed, true, "dishonest operator stake slashed");
    assert.equal(checks.challengerRewarded, true, "challenger rewarded");
    assert.ok(Number(row.bisectionRounds) > 0, "bisection ran");
    assert.ok(Number(row.leafCount) > 0 && (Number(row.leafCount) & (Number(row.leafCount) - 1)) === 0,
      "trace padded to a power of two");
  });
}
