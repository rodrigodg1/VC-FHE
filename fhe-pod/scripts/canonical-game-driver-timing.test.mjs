import test from "node:test";
import assert from "node:assert/strict";
import { advancePastDeadline, freshChainTimestamp } from "./canonical-game-driver.mjs";

test("deadline wait uses the remaining on-chain time instead of adding a fresh window", async () => {
  let timestamp = 100, advancedBy = null, absoluteTarget = null;
  const provider = {
    send: async (method, params) => {
      assert.equal(method, "eth_getBlockByNumber");
      assert.deepEqual(params, ["latest", false]);
      return { number: "0x1", timestamp: `0x${timestamp.toString(16)}` };
    },
    getBlock: async () => { throw new Error("cached getBlock must not be used when raw RPC is available"); }
  };
  const result = await advancePastDeadline(provider, async (seconds, targetTimestamp) => {
    advancedBy = seconds;
    absoluteTarget = targetTimestamp;
    // A block appears after the driver's deadline read. A real-chain waiter
    // must still target 121, rather than adding 21 seconds to this later block.
    timestamp = 107;
    timestamp = targetTimestamp;
  }, 120n);
  assert.equal(advancedBy, 21);
  assert.equal(absoluteTarget, 121);
  assert.deepEqual(result, { deadline: 120, observedTimestamp: 121 });
});

test("deadline wait does not delay a phase that is already open", async () => {
  const provider = { getBlock: async () => ({ number: 2, timestamp: 125 }) };
  let called = false;
  const result = await advancePastDeadline(provider, async () => { called = true; }, 120n);
  assert.equal(called, false);
  assert.deepEqual(result, { deadline: 120, observedTimestamp: 125 });
});

test("successive phase waits keep the contract deadlines after intervening transactions", async () => {
  let timestamp = 100;
  const provider = { getBlock: async () => ({ number: 2, timestamp }) };
  const waits = [];
  const advance = async (seconds, targetTimestamp) => {
    waits.push({ seconds, targetTimestamp });
    timestamp = targetTimestamp;
  };
  await advancePastDeadline(provider, advance, 120n);
  timestamp = 168; // verdict openings and diligence proof mined in this phase
  await advancePastDeadline(provider, advance, 240n);
  timestamp = 275; // challenge and trace-disclosure transactions mined next
  await advancePastDeadline(provider, advance, 360n);
  assert.deepEqual(waits, [
    { seconds: 21, targetTimestamp: 121 },
    { seconds: 73, targetTimestamp: 241 },
    { seconds: 86, targetTimestamp: 361 }
  ]);
});

test("deadline wait fails closed if the chain does not cross the deadline", async () => {
  const provider = { getBlock: async () => ({ number: 3, timestamp: 100 }) };
  await assert.rejects(advancePastDeadline(provider, async () => {}, 120n),
    /chain did not advance past the on-chain deadline/);
});

test("deadline wait rejects malformed timestamps", async () => {
  const provider = { getBlock: async () => ({ number: 4, timestamp: "invalid" }) };
  await assert.rejects(advancePastDeadline(provider, async () => {}, 120n), /invalid on-chain timestamp/);
});

test("fresh raw-RPC reads retry a transient missing head", async () => {
  let calls = 0;
  const provider = { send: async () => (++calls === 1 ? null : { timestamp: "0x7b" }) };
  assert.equal(await freshChainTimestamp(provider, { maxAttempts: 2, retryDelayMs: 0 }), 123);
  assert.equal(calls, 2);
});
