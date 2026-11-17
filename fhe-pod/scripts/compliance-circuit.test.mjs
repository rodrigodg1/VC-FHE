import test from "node:test";
import assert from "node:assert/strict";
import { compileComplianceCircuit, evaluateCircuitReference, validateCircuit } from "./compliance-circuit.mjs";

const options = { recordCount: 3, poorThresholdMilli: 2000, targetPermille: 950, targetCell: 7 };

test("explicit circuits preserve the terminal result, including positive results and padding", () => {
  for (const regional of [false, true]) {
    const circuit = compileComplianceCircuit({ ...options, regional });
    assert.equal(circuit.instructions.length & (circuit.instructions.length - 1), 0);
    const good = [3000, 3000, 3000], bad = [1000, 3000, 3000];
    const cells = regional ? [7, 7, 7] : [];
    assert.equal(evaluateCircuitReference(circuit, [...good, ...cells]).value, 1n);
    assert.equal(evaluateCircuitReference(circuit, [...bad, ...cells]).value, 0n);
    assert.ok(circuit.instructions.some(i => i.lhs.kind === "output" && i.lhs.index < i.index - 1));
  }
});

test("same public program handles equal-valued records without data-dependent wiring", () => {
  const circuit = compileComplianceCircuit(options);
  const frozen = JSON.stringify(circuit);
  for (const values of [[0, 0, 0], [1, 1, 1], [3000, 3000, 3000], [1000, 3000, 3000]]) {
    const expected = values.filter(v => v > 2000).length * 1000 >= values.length * 950 ? 1n : 0n;
    assert.equal(evaluateCircuitReference(circuit, values).value, expected);
    assert.equal(JSON.stringify(circuit), frozen);
  }
  assert.deepEqual(circuit.inputs.map(i => i.id), ["rating:0", "rating:1", "rating:2"]);
});

test("empty regional samples do not report observed compliance", () => {
  const circuit = compileComplianceCircuit({ ...options, regional: true });
  assert.equal(evaluateCircuitReference(circuit, [3000, 3000, 3000, 8, 8, 8]).value, 0n);
  assert.equal(evaluateCircuitReference(circuit, [3000, 1000, 1000, 7, 8, 8]).value, 1n);
});

test("malformed references, duplicate inputs and overflow fail before accepting a result", () => {
  const circuit = compileComplianceCircuit(options);
  for (const corrupt of [
    p => { p.instructions[0].lhs = { kind: "output", index: 0 }; },
    p => { p.inputs[1].id = p.inputs[0].id; },
    p => { p.output.index = 0; },
    p => { p.instructions[0].opcode = "SHL"; }
  ]) {
    const copy = structuredClone(circuit); corrupt(copy);
    assert.throws(() => validateCircuit(copy));
  }
  assert.throws(() => evaluateCircuitReference(circuit, [1n << 64n, 0, 0]));
});
