/**
 * Tests for the one-call orchestrator.
 *
 * The contract of prepareComputation() is that it either completes all seven
 * stages and returns a deployable artefact, or stops at the stage that failed
 * and explains why. It must never return a partially bound artefact.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { prepareComputation, renderSteps } from "../src/pipeline.mjs";

const STAGES = ["receive", "parse", "classify", "validate", "lower", "bind", "report"];

describe("successful runs complete all seven stages", () => {
  test("linear request", async () => {
    const r = await prepareComputation("x1 + x2 + x3", { taskLabel: "lin" });
    assert.equal(r.ok, true);
    assert.equal(r.steps.length, 7);
    assert.deepEqual(r.steps.map((s) => s.name), STAGES);
    assert.ok(r.steps.every((s) => s.status === "ok"));
    assert.equal(r.artifact.contract, "MKLHSVerification");
    assert.deepEqual(r.artifact.constructorArgs, ["toolkit-task", 1, 3, 0]);
    assert.ok(r.nextActions.length > 0);
  });

  test("non-linear request", async () => {
    const r = await prepareComputation("3*x1 + 2*x2 - x3",
      { inputs: { x1: 4, x2: 5, x3: 2 }, taskLabel: "nl" });
    assert.equal(r.ok, true);
    assert.equal(r.steps.length, 7);
    assert.equal(r.artifact.contract, "LegacyConfigurableDisputeGame");
    for (const k of ["inputRoot", "programRoot", "provenanceRoot"]) {
      assert.match(r.artifact.statement[k], /^0x[0-9a-f]{64}$/);
    }
    assert.equal(r.task.result, 20);
  });

  test("the lowering stage records the generated instructions", async () => {
    const r = await prepareComputation("x1 * x2", { inputs: { x1: 3, x2: 4 } });
    const lower = r.steps.find((s) => s.name === "lower");
    assert.ok(lower.data.instructions.some((i) => i.startsWith("MUL")));
  });

  test("the binding stage records the derived statement", async () => {
    const r = await prepareComputation("x1 * x2", { inputs: { x1: 3, x2: 4 } });
    const bind = r.steps.find((s) => s.name === "bind");
    assert.match(bind.data.programRoot, /^0x[0-9a-f]{64}$/);
    assert.match(bind.data.taskId, /^0x[0-9a-f]{64}$/);
  });
});

describe("rejected runs stop at the failing stage", () => {
  const cases = [
    ["sqrt(x1)", "E_UNSUPPORTED_OP"],
    ["x1 ^ 2", "E_UNSUPPORTED_OP"],
    ["1.5*x1", "E_UNSUPPORTED_LITERAL"],
    ["x1 +", "E_SYNTAX"],
    ["1 + 2", "E_NO_VARIABLES"],
  ];
  for (const [expr, code] of cases) {
    test(`"${expr}" is rejected with ${code} and yields no artefact`, async () => {
      const r = await prepareComputation(expr, { inputs: { x1: 1 } });
      assert.equal(r.ok, false);
      assert.equal(r.error.code, code);
      assert.equal(r.artifact, undefined, "a rejected run must not produce an artefact");
      assert.ok(r.steps.some((s) => s.status === "rejected"));
      assert.ok(r.steps.length < 7, "the pipeline must stop early");
    });
  }

  test("a negative intermediate is rejected rather than wrapped", async () => {
    const r = await prepareComputation("x1 - x2",
      { inputs: { x1: 2, x2: 5 }, forcePipeline: "non-linear" });
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "E_NEGATIVE_INTERMEDIATE");
  });

  test("missing inputs for a non-linear request are reported", async () => {
    const r = await prepareComputation("x1 * x2");
    assert.equal(r.ok, false);
    assert.equal(r.error.code, "E_MISSING_INPUTS");
    assert.ok(r.error.hint);
  });
});

describe("rendering", () => {
  test("renderSteps prints one line per stage with its status", async () => {
    const r = await prepareComputation("x1 + x2", { taskLabel: "r" });
    const text = renderSteps(r);
    for (const s of STAGES) assert.match(text, new RegExp(s));
    assert.match(text, /step 7/);
  });

  test("a rejection is rendered with the reason and the hint", async () => {
    const r = await prepareComputation("sqrt(x1)");
    const text = renderSteps(r);
    assert.match(text, /!!/);
    assert.match(text, /hint:/);
  });
});
