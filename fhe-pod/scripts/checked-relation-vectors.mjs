// Generate expected verdicts with the independent integer reference.
// stdout is consumed by the real-TFHE differential test.
import { evaluateLeaf, OPCODES } from "./micro-isa.mjs";
const max = (1n << 64n) - 1n;
const cases = Object.keys(OPCODES).map(opcode => [opcode, 257n, 3n]);
cases.push(
  ["ADD", max, 1n], ["ADD", max - 1n, 1n],
  ["SUB", 0n, 1n], ["SUB", 1n, 1n],
  ["MUL", max, 2n], ["MUL", max, 1n], ["MUL", max, 0n],
  ["DIV", 1n, 0n], ["MOD", 1n, 0n],
  ["SHR", max, 63n], ["SHR", max, 64n],
  ["ADD_CHAIN", max - 7n, 8n], ["ADD_CHAIN", max - 8n, 8n],
  ["ADD_CHAIN", 1n, 0n], ["ADD_CHAIN", 1n, 9n],
  ["CAST_U8", 256n, 0n]
);
console.log(JSON.stringify(cases.map(([opcode, lhs, rhs]) => {
  const expected = evaluateLeaf(opcode, lhs, rhs);
  return { opcode, lhs: String(lhs), rhs: String(rhs), valid: expected.valid,
    value: expected.value === null ? null : String(expected.value) };
})));
