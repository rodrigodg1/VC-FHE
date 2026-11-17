/**
 * On-chain verification tests for the LINEAR QoE examples (real-TFHE payload,
 * production MKLHS-Verification.sol, standalone Hardhat JSON-RPC node).
 *
 * Requires the real-TFHE payload:
 *   npm run cases:generate && npm run emit:tfhe
 *
 * Run: npm run test:linear
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  loadPayload, startHardhatNode, runCaseOnChain,
} from "../linear/run-onchain.mjs";

const payload = loadPayload();

test("linear QoE cases verify end to end on a Hardhat node", async (t) => {
  const node = await startHardhatNode(8573);
  t.after(() => node.child.kill("SIGKILL"));

  for (const entry of payload.sizes) {
    await t.test(`${entry.label}: full on-chain verification matrix`, async () => {
      const result = await runCaseOnChain({
        provider: node.provider,
        entry,
        gens: payload.commit_generators,
      });
      assert.equal(result.accepted, true, "honest result accepted on-chain");
      assert.equal(result.wrongKeyRejected, true, "wrong-key admission rejected");
      assert.equal(result.omissionRejected, true, "omission rejected");
      assert.equal(result.replayRejected, true, "replay rejected");
      assert.equal(result.tamperAccepted, false, "substituted output rejected by verifyBound");
      assert.equal(result.tamperSubmitRejected, true, "substituted output submit reverted");
      assert.equal(result.digestMatch, true, "consumer digest matches on-chain record");
      assert.equal(result.commitmentMatch, true, "consumer commitment matches on-chain record");
      assert.equal(result.decryptChecked, true, "exact TFHE decryption asserted at emission");
    });
  }
});

test("payload carries real QoE values and in-regime aggregates", () => {
  const byLabel = Object.fromEntries(payload.sizes.map((e) => [e.label, e]));

  const mean = byLabel["stav360-session-mos-mean"];
  assert.ok(mean, "STAV360 mean case present");
  assert.equal(mean.n, 16);
  assert.ok(mean.values.every((v) => v >= 1 && v <= 5), "ACR 1..5 ratings");
  assert.equal(
    Number(mean.expected_plaintext),
    mean.values.reduce((a, b) => a + b, 0),
    "verified sum equals the sum of the real ratings"
  );

  const rate = byLabel["drivetest-compliance-rate"];
  assert.ok(rate, "drive-test compliance case present");
  assert.equal(rate.n, 16);
  assert.ok(rate.values.every((v) => v === 0 || v === 1), "0/1 indicators");
  assert.equal(
    Number(rate.expected_plaintext),
    rate.values.reduce((a, b) => a + b, 0),
    "verified sum equals the good-session count"
  );
  // Same real panel as the evaluation's regulatory fixture: 12 of 16 good.
  assert.equal(Number(rate.expected_plaintext), 12);
  assert.equal(12 * 1000 >= 16 * 950, false, "panel is a compliance violation");
});
