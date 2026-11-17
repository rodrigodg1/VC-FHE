/**
 * Tests for the deployment layer: expression -> on-chain statement.
 *
 * The guarantee under test is that the automatically derived statement is the
 * same one the existing tooling would produce for the same instructions, so
 * nothing about the protocol or its verification changes.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { defineComputation, buildDeploymentArtifact, compileToDeployment } from "../src/index.mjs";
import { productionEvmLib } from "../src/deployment.mjs";

const BYTES32 = /^0x[0-9a-f]{64}$/;

describe("linear pipeline: constructor arguments", () => {
  test("emits positional arguments in the contract's order", async () => {
    const { artifact } = await compileToDeployment("x1 + x2 + x3", { taskLabel: "t-lin" });
    assert.equal(artifact.contract, "MKLHSVerification");
    assert.deepEqual(artifact.constructorArgs, ["toolkit-task", 1, 3, 0]);
    assert.equal(artifact.constructorArgsNamed.operationName, "SUM");
    assert.match(artifact.taskId, BYTES32);
  });

  test("SUB maps to allowedOperation 1", async () => {
    const { artifact } = await compileToDeployment("x1 - x2 - x3");
    assert.equal(artifact.constructorArgsNamed.allowedOperation, 1);
    assert.equal(artifact.constructorArgsNamed.operationName, "SUB");
  });

  test("no micro-trace or roots are produced for the linear path", async () => {
    const { artifact } = await compileToDeployment("x1 + x2");
    assert.equal(artifact.statement, undefined);
    assert.equal(artifact.trace, undefined);
  });
});

describe("non-linear pipeline: authenticated statement", () => {
  test("derives the three roots as well-formed bytes32", async () => {
    const { artifact } = await compileToDeployment("3*x1 + 2*x2 - x3",
      { inputs: { x1: 4, x2: 5, x3: 2 }, taskLabel: "t-nl" });
    assert.equal(artifact.contract, "LegacyConfigurableDisputeGame");
    for (const k of ["inputRoot", "programRoot", "provenanceRoot"]) {
      assert.match(artifact.statement[k], BYTES32, `${k} must be bytes32`);
    }
    assert.equal(artifact.result, 20);
    assert.equal(artifact.trace.witnesses.length, artifact.trace.leafCount);
  });

  test("roots equal what the production builder produces for the same leaves", async () => {
    const evm = await productionEvmLib();
    const task = await defineComputation("x1*x1 + x2*x2", { inputs: { x1: 3, x2: 4 } });
    const { artifact } = await compileToDeployment("x1*x1 + x2*x2",
      { inputs: { x1: 3, x2: 4 }, taskLabel: "same" });

    // Recompute independently through the production API.
    const ethersMod = await import(new URL(`file://${(await import("node:path")).default.join(
      (await import("../src/compiler.mjs")).VCFHE_ROOT, "fhe-pod", "scripts", "evm-lib.mjs")}`).href);
    void ethersMod;
    const expected = evm.buildAuthenticatedTracePlan(
      artifact.taskId, task.trace.witnesses,
      "0x0000000000000000000000000000000000000000");

    assert.equal(artifact.statement.inputRoot, expected.inputTree.root);
    assert.equal(artifact.statement.programRoot, expected.programTree.root);
    assert.equal(artifact.statement.provenanceRoot, expected.provenanceTree.root);
  });

  test("the statement is deterministic for the same expression and inputs", async () => {
    const a = await compileToDeployment("gt(x1*x1, 25)", { inputs: { x1: 6 }, taskLabel: "det" });
    const b = await compileToDeployment("gt(x1*x1, 25)", { inputs: { x1: 6 }, taskLabel: "det" });
    assert.deepEqual(a.artifact.statement, b.artifact.statement);
    assert.equal(a.artifact.taskId, b.artifact.taskId);
  });

  test("different instructions produce a different program root", async () => {
    const a = await compileToDeployment("x1 * x2", { inputs: { x1: 2, x2: 3 }, taskLabel: "k" });
    const b = await compileToDeployment("x1 + x2", { inputs: { x1: 2, x2: 3 }, taskLabel: "k", forcePipeline: "non-linear" });
    assert.notEqual(a.artifact.statement.programRoot, b.artifact.statement.programRoot);
  });

  test("input records are emitted for the trace operands", async () => {
    const { artifact } = await compileToDeployment("x1 + x2", {
      inputs: { x1: 7, x2: 8 }, forcePipeline: "non-linear",
      inputOwner: "0x1111111111111111111111111111111111111111",
    });
    assert.ok(Array.isArray(artifact.inputRecords));
    assert.ok(artifact.inputRecords.length > 0);
  });
});

describe("regression: production tooling is only read, never altered", () => {
  test("buildAuthenticatedTracePlan remains callable and pure across toolkit use", async () => {
    const evm = await productionEvmLib();
    const leaves = (await defineComputation("x1 + x2", { inputs: { x1: 1, x2: 2 }, forcePipeline: "non-linear" })).trace.witnesses;
    const id = "0x" + "ab".repeat(32);
    const owner = "0x0000000000000000000000000000000000000000";
    const first = evm.buildAuthenticatedTracePlan(id, leaves, owner);
    await compileToDeployment("x1 * x2 + x3", { inputs: { x1: 1, x2: 2, x3: 3 } });
    const second = evm.buildAuthenticatedTracePlan(id, leaves, owner);
    assert.equal(second.inputTree.root, first.inputTree.root);
    assert.equal(second.programTree.root, first.programTree.root);
    assert.equal(second.provenanceTree.root, first.provenanceTree.root);
  });
});
