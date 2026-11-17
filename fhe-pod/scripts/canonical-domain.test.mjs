import test from "node:test";
import assert from "node:assert/strict";
import { admitCanonicalDomain } from "./canonical-domain.mjs";
import { compileComplianceCircuit } from "./compliance-circuit.mjs";
import { OPCODES, evaluateLeaf } from "./micro-isa.mjs";
const con = value => ({ kind: "constant", value: String(value) });
const prog = (opcode, rhs = { kind: "input", index: 1 }) => ({ version: "compliance-explicit-dag-v1",
  inputs: [{ id: "a", type: "uint64" }, { id: "b", type: "uint64" }],
  instructions: [{ index: 0, opcode, lhs: { kind: "input", index: 0 }, rhs }], output: { kind: "output", index: 0 } });
test("public intervals enclose the independent integer reference for all fifteen opcodes", () => {
  for (const opcode of Object.keys(OPCODES)) {
    const scalar = ["DIV", "MOD", "SHR", "ADD_CHAIN"].includes(opcode);
    const p = prog(opcode, scalar ? con(3) : undefined);
    const bounds = [{ min: "256", max: "300" }, { min: "1", max: "8" }];
    const range = admitCanonicalDomain(p, bounds).outputBounds[0];
    for (let a = 256; a <= 300; a++) for (let b = 1; b <= 8; b++) {
      const result = evaluateLeaf(opcode, BigInt(a), BigInt(scalar ? 3 : b));
      assert.equal(result.valid, true);
      assert.ok(BigInt(result.value) >= BigInt(range.min) && BigInt(result.value) <= BigInt(range.max), opcode);
    }
  }
});
test("possible errors are rejected before any FHE evaluation", () => {
  const bounds = [{ min: "0", max: "18446744073709551615" }, { min: "1", max: "2" }];
  for (const opcode of ["ADD", "SUB", "MUL"]) assert.throws(() => admitCanonicalDomain(prog(opcode), bounds));
  for (const [opcode, value] of [["DIV", 0], ["MOD", 0], ["SHR", 64], ["ADD_CHAIN", 0], ["ADD_CHAIN", 9]]) {
    assert.throws(() => admitCanonicalDomain(prog(opcode, con(value)), bounds));
  }
});
test("both compliance circuits fit the checked domain on encrypted ratings and cells", () => {
  for (const regional of [false, true]) {
    const p = compileComplianceCircuit({ recordCount: 16, regional, poorThresholdMilli: 2000, targetPermille: 950, targetCell: 7 });
    const ranges = p.inputs.map(i => ({ min: "0", max: i.id.startsWith("rating:") ? "5000" : "4294967295" }));
    assert.equal(admitCanonicalDomain(p, ranges).outputBounds.at(-1).max, "1");
  }
});
