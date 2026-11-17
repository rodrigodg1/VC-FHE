/**
 * Test suite for the additive high-level layer.
 *
 * The suite is organised around the guarantee that matters: the toolkit must
 * produce instructions that are indistinguishable from hand-written ones, and
 * it must never silently change the semantics of a computation.
 *
 * Run:  npm test        (from VC-FHE/toolkit)
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { defineComputation, inspectExpression, CompilationError, ExpressionError } from "../src/index.mjs";
import { productionLowering } from "../src/compiler.mjs";

const strip = (w) => ({ leaf_index: w.leaf_index, opcode: w.opcode, opcode_name: w.opcode_name, lhs: w.lhs, rhs: w.rhs, claimed: w.claimed });

// ---------------------------------------------------------------- 1 + 3
describe("1/3. equivalence with manually written instructions", () => {
  test("generated trace equals a hand-written trace, leaf for leaf", async () => {
    const { leaf } = await productionLowering();
    // Manual encoding of 3*x1 + 2*x2 - x3 with x1=4, x2=5, x3=2.
    const manual = [
      leaf(0, "MUL", 3, 4, 12, "x1*3"),
      leaf(1, "MUL", 2, 5, 10, "x2*2"),
      leaf(2, "ADD", 12, 10, 22, "sum"),
      leaf(3, "SUB", 22, 2, 20, "minus x3"),
    ];
    const task = await defineComputation("3*x1 + 2*x2 - x3", { inputs: { x1: 4, x2: 5, x3: 2 } });
    assert.equal(task.trace.witnesses.length, manual.length);
    task.trace.witnesses.forEach((w, i) => {
      assert.deepEqual(strip(w), strip(manual[i]), `leaf ${i} differs from the manual encoding`);
    });
  });

  test("opcode numbering comes from the production module, not a local copy", async () => {
    const { OPCODES } = await productionLowering();
    const task = await defineComputation("x1 * x2 + x3", { inputs: { x1: 2, x2: 3, x3: 4 } });
    for (const w of task.trace.witnesses) {
      assert.equal(w.opcode, OPCODES[w.opcode_name], `opcode number for ${w.opcode_name} diverges from production`);
    }
  });

  test("trace shape is contract-compatible: power-of-two leaves and log2 rounds", async () => {
    const task = await defineComputation("x1*x1 + x2*x2 + x3*x3", { inputs: { x1: 1, x2: 2, x3: 3 } });
    const n = task.trace.leafCount;
    assert.equal(n & (n - 1), 0, "leaf count must be a power of two");
    assert.equal(task.trace.bisectionRounds, Math.ceil(Math.log2(n)));
    task.trace.witnesses.forEach((w, i) => assert.equal(w.leaf_index, i));
  });
});

// -------------------------------------------------------------------- 2
describe("2. result equivalence", () => {
  const cases = [
    ["3*x1 + 2*x2 - x3", { x1: 4, x2: 5, x3: 2 }, 20],
    ["x1 * x2", { x1: 6, x2: 7 }, 42],
    ["(x1 + x2) * x3", { x1: 2, x2: 3, x3: 4 }, 20],
    ["x1 / x2", { x1: 9, x2: 2 }, 4],           // integer division
    ["x1 % x2", { x1: 9, x2: 4 }, 1],
    ["gt(x1, x2)", { x1: 5, x2: 3 }, 1],
    ["lt(x1, x2)", { x1: 5, x2: 3 }, 0],
    ["min(x1, x2)", { x1: 5, x2: 3 }, 3],
    ["and(x1, x2)", { x1: 6, x2: 3 }, 2],
    ["shr(x1, x2)", { x1: 16, x2: 2 }, 4],
  ];
  for (const [expr, inputs, expected] of cases) {
    test(`${expr} evaluates to ${expected}`, async () => {
      const task = await defineComputation(expr, { inputs });
      assert.equal(task.result, expected);
      const last = task.trace.witnesses[task.trace.realInstructions - 1];
      assert.equal(last.claimed, expected, "final instruction must claim the result");
    });
  }
});

// -------------------------------------------------------------------- 4
describe("4. valid linear expressions route to the linear pipeline", () => {
  test("sum of distinct variables -> SUM", () => {
    const r = inspectExpression("x1 + x2 + x3");
    assert.equal(r.pipeline, "linear");
    assert.equal(r.operation, "SUM");
  });
  test("first positive, rest negative -> SUB", () => {
    const r = inspectExpression("x1 - x2 - x3");
    assert.equal(r.pipeline, "linear");
    assert.equal(r.operation, "SUB");
  });
  test("linear task carries deployment arguments and needs no inputs", async () => {
    const task = await defineComputation("x1 + x2 + x3 + x4");
    assert.equal(task.pipeline, "linear");
    const a = task.deployment.constructorArgs;
    assert.equal(a.allowedOperation, 0);
    assert.equal(a.totalItems, 4);
    assert.equal(task.trace, undefined, "the linear path has no micro-trace");
  });
  test("weighted linear is NOT accepted by the linear contract", async () => {
    const r = inspectExpression("3*x1 + 2*x2 - x3");
    assert.equal(r.pipeline, "non-linear");
    await assert.rejects(
      () => defineComputation("3*x1 + 2*x2 - x3", { inputs: { x1: 1, x2: 1, x3: 1 }, forcePipeline: "linear" }),
      (e) => e instanceof CompilationError && e.code === "E_NOT_LINEAR_VERIFIABLE"
    );
  });
  test("affine expression with a constant offset is not linear-verifiable", () => {
    assert.equal(inspectExpression("x1 + x2 + 5").pipeline, "non-linear");
  });
});

// -------------------------------------------------------------------- 5
describe("5. supported non-linear expressions", () => {
  test("variance-shaped expression lowers to a trace", async () => {
    const task = await defineComputation("(x1*x1 + x2*x2) / 2", { inputs: { x1: 3, x2: 5 } });
    assert.equal(task.pipeline, "non-linear");
    assert.equal(task.result, 17);
    assert.ok(task.trace.witnesses.some((w) => w.opcode_name === "MUL"));
    assert.ok(task.trace.witnesses.some((w) => w.opcode_name === "DIV"));
  });
  test("nested predicate composition", async () => {
    const task = await defineComputation("and(gt(x1, 2), lt(x2, 10))", { inputs: { x1: 5, x2: 4 } });
    assert.equal(task.result, 1);
  });
});

// -------------------------------------------------------------------- 6
describe("6. operator precedence and parentheses", () => {
  test("multiplication binds tighter than addition", async () => {
    const a = await defineComputation("x1 + x2 * x3", { inputs: { x1: 2, x2: 3, x3: 4 } });
    assert.equal(a.result, 14);
  });
  test("parentheses override precedence", async () => {
    const b = await defineComputation("(x1 + x2) * x3", { inputs: { x1: 2, x2: 3, x3: 4 } });
    assert.equal(b.result, 20);
  });
  test("subtraction is left-associative", async () => {
    const c = await defineComputation("x1 - x2 - x3", { inputs: { x1: 10, x2: 3, x3: 2 }, forcePipeline: "non-linear" });
    assert.equal(c.result, 5);
  });
  test("division and modulo bind at the same level as multiplication", async () => {
    const d = await defineComputation("x1 + x2 / x3", { inputs: { x1: 1, x2: 9, x3: 2 } });
    assert.equal(d.result, 5);
  });
});

// -------------------------------------------------------------------- 7
describe("7. constants, negatives and variable counts", () => {
  test("constant folding on coefficients", async () => {
    const t = await defineComputation("2*3*x1", { inputs: { x1: 5 } });
    assert.equal(t.result, 30);
  });
  test("negative inputs are rejected: the micro-ISA is unsigned", async () => {
    await assert.rejects(
      () => defineComputation("x1 + x2", { inputs: { x1: -1, x2: 2 }, forcePipeline: "non-linear" }),
      (e) => e instanceof CompilationError && e.code === "E_NEGATIVE_INPUT"
    );
  });
  test("a negative intermediate value is rejected rather than wrapped", async () => {
    await assert.rejects(
      () => defineComputation("x1 - x2", { inputs: { x1: 2, x2: 5 }, forcePipeline: "non-linear" }),
      (e) => e instanceof CompilationError && e.code === "E_NEGATIVE_INTERMEDIATE"
    );
  });
  test("variable count is reflected in the linear deployment arguments", async () => {
    for (const n of [2, 3, 8]) {
      const expr = Array.from({ length: n }, (_, i) => `x${i + 1}`).join(" + ");
      const task = await defineComputation(expr);
      assert.equal(task.deployment.constructorArgs.totalItems, n);
    }
  });
  test("missing input is reported explicitly", async () => {
    await assert.rejects(
      () => defineComputation("x1 * x2", { inputs: { x1: 2 } }),
      (e) => e instanceof CompilationError && e.code === "E_MISSING_INPUT"
    );
  });
});

// -------------------------------------------------------------------- 8
describe("8. unsupported operations are rejected", () => {
  const rejected = [
    ["sqrt(x1)", "E_UNSUPPORTED_OP"],
    ["exp(x1)", "E_UNSUPPORTED_OP"],
    ["log(x1)", "E_UNSUPPORTED_OP"],
    ["x1 ^ 2", "E_UNSUPPORTED_OP"],
    ["1.5 * x1", "E_UNSUPPORTED_LITERAL"],
  ];
  for (const [expr, code] of rejected) {
    test(`${expr} is rejected with ${code}`, () => {
      assert.throws(() => inspectExpression(expr), (e) => (e.code === code));
    });
  }
  test("division by zero is rejected", async () => {
    await assert.rejects(
      () => defineComputation("x1 / 0", { inputs: { x1: 4 } }),
      (e) => e.code === "E_DIV_ZERO"
    );
  });
  test("rejection explains why and suggests an alternative", () => {
    try { inspectExpression("x1 ^ 2"); assert.fail("should have thrown"); }
    catch (e) { assert.match(e.hint ?? "", /x1\*x1/); }
  });
});

// -------------------------------------------------------------------- 9
describe("9. malformed or ambiguous input is rejected", () => {
  const bad = ["", "   ", "x1 +", "+ x1", "x1 x2", "(x1 + x2", "x1 + x2)", "min(x1)", "gt(x1, x2, x3)", "y = x1 + x2", "x1 @ x2"];
  for (const expr of bad) {
    test(`"${expr}" is rejected`, () => {
      assert.throws(() => inspectExpression(expr), (e) => e instanceof ExpressionError || e instanceof CompilationError);
    });
  }
  test("an expression without variables is rejected", async () => {
    await assert.rejects(() => defineComputation("1 + 2"), (e) => e.code === "E_NO_VARIABLES");
  });
});

// ------------------------------------------------------------------- 10
describe("10. regression: the existing implementation is untouched", () => {
  test("production opcode table has its 15 entries with stable numbering", async () => {
    const { OPCODES } = await productionLowering();
    assert.equal(Object.keys(OPCODES).length, 15);
    assert.deepEqual(OPCODES, {
      MUL: 1, SHR: 2, CAST_U8: 3, MIN: 4, BITAND: 5, ADD: 6, SUB: 7,
      DIV: 8, MOD: 9, EQ: 10, LT: 11, GT: 12, BITOR: 13, BITXOR: 14, ADD_CHAIN: 15,
    });
  });
  test("production workload lowering still runs and is unaffected by the toolkit", async () => {
    const mod = await productionLowering();
    assert.equal(typeof mod.lowerWorkloadSpec, "function");
    assert.ok(mod.LOWERING_ENGINE_VERSION);
    const specs = mod.defaultApplicationWorkloads ?? mod.applicationWorkloadSpecs;
    assert.ok(specs, "production workload specs must still be exported");
  });
  test("the toolkit only reads from the production module", async () => {
    const { OPCODES } = await productionLowering();
    const before = JSON.stringify(OPCODES);
    await defineComputation("x1 * x2 + x3", { inputs: { x1: 1, x2: 2, x3: 3 } });
    const { OPCODES: after } = await productionLowering();
    assert.equal(JSON.stringify(after), before, "production state must not change");
  });
});

// ------------------------------------------------------- inspection output
describe("inspection before execution", () => {
  test("explain() shows the expression, classification and every instruction", async () => {
    const task = await defineComputation("3*x1 + 2*x2 - x3", { inputs: { x1: 4, x2: 5, x3: 2 } });
    const text = task.explain();
    assert.match(text, /expression : 3\*x1 \+ 2\*x2 - x3/);
    assert.match(text, /pipeline   : non-linear/);
    assert.match(text, /MUL/);
    assert.match(text, /result     : 20/);
  });
  test("toConfig() is serialisable and carries the trace", async () => {
    const task = await defineComputation("x1 * x2", { inputs: { x1: 3, x2: 4 } });
    const cfg = JSON.parse(JSON.stringify(task.toConfig()));
    assert.equal(cfg.pipeline, "non-linear");
    assert.equal(cfg.trace.witnesses.length, cfg.trace.leafCount);
    assert.equal(cfg.result, 12);
  });
});
