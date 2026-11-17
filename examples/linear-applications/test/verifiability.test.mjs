/**
 * Verifiability matrix for every linear-application example.
 *
 * For EACH application the suite checks, against the production contract:
 *   (a) the honest flow is accepted on-chain and matched by the consumer;
 *   (b) a tampered output commitment is rejected (verifyBound false and
 *       submitResultBound reverts);
 *   (c) an admission signed under the wrong key is rejected;
 *   (d) omission of one record blocks result submission;
 *   (e) a divergent DELIVERED artifact is detected by the consumer check
 *       even though the on-chain record is honest.
 *
 * Run: npm test   (node --test, Node >= 18)
 */
import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  mklhs, newChain, deployWithKeys, admitAll, submitResult,
  consumerVerify, decrypt, reverts, runHonest, GAS,
} from "../lib/scenario.mjs";
import * as mean from "../01-mean-aggregate/run.mjs";
import * as rate from "../02-compliance-rate/run.mjs";
import * as margin from "../03-margin-vs-reference/run.mjs";
import * as variance from "../04-variance-sufficient-stats/run.mjs";

const APPLICATIONS = [
  {
    name: "01-mean-aggregate",
    build: () => mean.scenario("mean-test"),
    datasetRef: "test/01-mean",
    interpret: (plain) => {
      const n = BigInt(mean.RATINGS.length);
      const expected = mean.RATINGS.reduce((a, b) => a + b, 0n);
      assert.equal(plain, expected, "verified sum must equal plaintext sum");
      assert.equal(Number(plain) / Number(n), 3.6, "mean of the demo ratings");
    },
  },
  {
    name: "02-compliance-rate",
    build: () => rate.scenario("rate-test"),
    datasetRef: "test/02-rate",
    interpret: (plain) => {
      const expected = rate.INDICATORS.reduce((a, b) => a + b, 0n);
      assert.equal(plain, expected, "verified count must equal number of 1-indicators");
    },
  },
  {
    name: "03-margin-vs-reference (SUB)",
    build: () => margin.scenario("margin-test"),
    datasetRef: "test/03-margin",
    interpret: (plain) => {
      const expected = margin.USAGE.reduce((a, u) => a - u, margin.ALLOWANCE);
      assert.equal(plain, expected, "verified margin must equal reference minus usages");
    },
  },
  {
    name: "04-variance-sufficient-stats (S1 = sum x)",
    build: () => variance.scenarioS1("variance-test-s1"),
    datasetRef: "test/04-variance-s1",
    interpret: (plain) => {
      const expected = variance.SAMPLES.reduce((a, b) => a + b, 0n);
      assert.equal(plain, expected, "verified S1 must equal plaintext sum");
    },
  },
];

for (const app of APPLICATIONS) {
  test(`${app.name}: verifiability matrix`, async (t) => {
    const chain = await newChain();

    await t.test("(a) honest flow accepted on-chain and matched by consumer", async () => {
      const s = app.build();
      const { bound, consumer, plain } = await runHonest({
        chain, scenario: s, datasetRef: app.datasetRef, taskLabel: `${app.name}-honest`,
      });
      assert.equal(bound.accepted, true);
      assert.equal(consumer.ok, true);
      assert.equal(plain, s.expectedPlain);
      app.interpret(plain);
    });

    await t.test("(b) tampered output commitment rejected on-chain", async () => {
      const s = app.build();
      const ctx = await deployWithKeys({ chain, scenario: s, datasetRef: app.datasetRef });
      await admitAll({ contract: ctx.contract, scenario: s, ownerSigner: ctx.ownerSigner });

      // Adversarial operator: submits the commitment of a single input record
      // instead of the authorized aggregate.
      const tampered = s.records[0].commitment;
      const ok = await ctx.contract.verifyBound(mklhs.g1ToContract(tampered));
      assert.equal(ok, false, "verifyBound must reject a non-aggregate commitment");

      const taskId = ethers.keccak256(ethers.toUtf8Bytes(`${app.name}-tamper`));
      await (await ctx.contract.connect(ctx.deployer).registerTask(
        taskId, await ctx.operator.getAddress(), GAS)).wait();
      await (await ctx.contract.connect(ctx.operator).depositStake(
        { value: ethers.parseEther("1"), ...GAS })).wait();
      const rejected = await reverts(ctx.contract.connect(ctx.operator).submitResultBound(
        taskId, s.outputDigest, mklhs.g1ToContract(tampered), GAS));
      assert.equal(rejected, true, "submitResultBound must revert on tampered commitment");
    });

    await t.test("(c) admission signed under the wrong key rejected", async () => {
      const s = app.build();
      const ctx = await deployWithKeys({ chain, scenario: s, datasetRef: app.datasetRef });
      const adversary = mklhs.keygen(mklhs.makeRng(`${app.name}-adversary`));
      const forged = mklhs.sign(adversary.sk, s.records[0].commitment, s.tagHex, 0);
      const rejected = await reverts(ctx.contract.connect(ctx.ownerSigner(0)).admitRecord(
        0,
        mklhs.g1ToContract(s.records[0].commitment),
        mklhs.g1ToContract(forged),
        GAS
      ));
      assert.equal(rejected, true, "admitRecord must revert when signature key != registered key");
    });

    await t.test("(d) omission of one record blocks result submission", async () => {
      const s = app.build();
      const ctx = await deployWithKeys({ chain, scenario: s, datasetRef: app.datasetRef });
      await admitAll({
        contract: ctx.contract, scenario: s, ownerSigner: ctx.ownerSigner,
        skipIndices: [s.n - 1],
      });
      const taskId = ethers.keccak256(ethers.toUtf8Bytes(`${app.name}-omit`));
      await (await ctx.contract.connect(ctx.deployer).registerTask(
        taskId, await ctx.operator.getAddress(), GAS)).wait();
      await (await ctx.contract.connect(ctx.operator).depositStake(
        { value: ethers.parseEther("1"), ...GAS })).wait();
      const rejected = await reverts(ctx.contract.connect(ctx.operator).submitResultBound(
        taskId, s.outputDigest, mklhs.g1ToContract(s.outputCommitment), GAS));
      assert.equal(rejected, true, "submitResultBound must revert while admissions are incomplete");
    });

    await t.test("(e) divergent delivered artifact detected by consumer", async () => {
      const s = app.build();
      const { bound } = await runHonest({
        chain, scenario: s, datasetRef: app.datasetRef, taskLabel: `${app.name}-delivery`,
      });
      // Operator delivers a different artifact than the one bound on-chain.
      const divergent = s.outputCt.map((c, i) => (i === 0 ? mklhs.mod(c + 1n, mklhs.R) : c));
      const consumer = consumerVerify({ deliveredCoords: divergent, gens: s.gens, bound });
      assert.equal(consumer.ok, false, "consumer must reject a divergent delivery");
      // The honest delivery still matches (sanity).
      const honest = consumerVerify({ deliveredCoords: s.outputCt, gens: s.gens, bound });
      assert.equal(honest.ok, true);
    });
  });
}

test("04-variance: both verified sums decrypt to the variance sufficient statistics", async () => {
  const chain = await newChain();
  const s1 = variance.scenarioS1("variance-e2e-s1");
  const s2 = variance.scenarioS2("variance-e2e-s2");
  const r1 = await runHonest({
    chain, scenario: s1, datasetRef: "test/04-variance-s1-e2e", taskLabel: "var-s1",
  });
  const r2 = await runHonest({
    chain, scenario: s2, datasetRef: "test/04-variance-s2-e2e", taskLabel: "var-s2",
  });
  const n = Number(variance.SAMPLES.length);
  const S1 = Number(r1.plain);
  const S2 = Number(r2.plain);
  const meanVal = S1 / n;
  const varVal = S2 / n - meanVal * meanVal;
  const xs = variance.SAMPLES.map(Number);
  const expectedMean = xs.reduce((a, b) => a + b, 0) / n;
  const expectedVar = xs.reduce((a, b) => a + (b - expectedMean) ** 2, 0) / n;
  assert.equal(meanVal, expectedMean);
  assert.ok(Math.abs(varVal - expectedVar) < 1e-9, "variance from verified sums matches direct computation");
});
