// Explicit circuits for the two canonical workloads. Compilation consumes
// public dimensions and constants only; private values never select a wire.
import { evaluateLeaf, OPCODES } from "./micro-isa.mjs";

export const COMPLIANCE_CIRCUIT_VERSION = "compliance-explicit-dag-v1";

function natural(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) throw new Error(`invalid ${label}`);
  return value;
}

export function compileComplianceCircuit({ recordCount, regional = false,
  poorThresholdMilli, targetPermille, targetCell = 0 }) {
  natural(recordCount, "recordCount", 2);
  natural(poorThresholdMilli, "poorThresholdMilli", 1);
  natural(targetPermille, "targetPermille", 1);
  natural(targetCell, "targetCell");
  if (targetPermille > 1000) throw new Error("targetPermille exceeds 1000");
  const inputs = [], instructions = [];
  const constant = value => ({ kind: "constant", value: String(value) });
  const input = id => {
    const ref = { kind: "input", index: inputs.length };
    inputs.push({ id, type: "uint64" }); return ref;
  };
  const emit = (opcode, lhs, rhs) => {
    const ref = { kind: "output", index: instructions.length };
    instructions.push({ index: ref.index, opcode, lhs, rhs }); return ref;
  };
  const sum = values => {
    let layer = [...values];
    let size = 1; while (size < layer.length) size *= 2;
    while (layer.length < size) layer.push(constant(0));
    while (layer.length > 1) {
      const next = [];
      for (let i = 0; i < layer.length; i += 2) next.push(emit("ADD", layer[i], layer[i + 1]));
      layer = next;
    }
    return layer[0];
  };
  const ratings = Array.from({ length: recordCount }, (_, i) => input(`rating:${i}`));
  const cells = regional ? Array.from({ length: recordCount }, (_, i) => input(`cell:${i}`)) : [];
  const inArea = cells.map(cell => emit("EQ", cell, constant(targetCell)));
  const good = ratings.map(rating => emit("GT", rating, constant(poorThresholdMilli)));
  const selectedGood = regional ? good.map((bit, i) => emit("BITAND", inArea[i], bit)) : good;
  const count = regional ? sum(inArea) : constant(recordCount);
  const goodCount = sum(selectedGood);
  const scaledGood = emit("MUL", goodCount, constant(1000));
  const required = emit("MUL", count, constant(targetPermille));
  const violation = emit("LT", scaledGood, required);
  let result = emit("BITXOR", violation, constant(1));
  // A positive regional result requires observations; zero does not distinguish
  // an empty sample from a failing quality threshold. No fraction 0/0 is used.
  if (regional) result = emit("BITAND", result, emit("GT", count, constant(0)));
  const unpaddedLength = instructions.length;
  let size = 1; while (size < instructions.length) size *= 2;
  while (instructions.length < size) result = emit("ADD", result, constant(0));
  return { version: COMPLIANCE_CIRCUIT_VERSION, integerDomain: "checked-uint64",
    inputs, instructions, output: result, unpaddedLength,
    predicate: regional ? "nonempty-and-share-meets-target" : "share-meets-target" };
}

export function validateCircuit(program) {
  if (program.version !== COMPLIANCE_CIRCUIT_VERSION || !Array.isArray(program.inputs) ||
      !Array.isArray(program.instructions) || !program.instructions.length) throw new Error("invalid circuit");
  const ids = program.inputs.map(input => input.id);
  if (new Set(ids).size !== ids.length || program.inputs.some(input => input.type !== "uint64")) {
    throw new Error("ambiguous input identifiers or types");
  }
  const ref = (source, before) => {
    if (source?.kind === "constant" && /^\d+$/.test(source.value) && BigInt(source.value) < (1n << 64n)) return;
    if (!Number.isInteger(source?.index) || source.index < 0) throw new Error("invalid source index");
    if (source.kind === "input" && source.index < program.inputs.length) return;
    if (source.kind === "output" && source.index < before) return;
    throw new Error("source is missing, forward or cyclic");
  };
  program.instructions.forEach((instruction, i) => {
    if (instruction.index !== i || !Object.hasOwn(OPCODES, instruction.opcode)) throw new Error("invalid instruction");
    ref(instruction.lhs, i); ref(instruction.rhs, i);
    if (["DIV", "MOD", "SHR", "ADD_CHAIN"].includes(instruction.opcode) && instruction.rhs.kind !== "constant") {
      throw new Error("control operand must be public");
    }
  });
  if (program.output?.kind !== "output" || program.output.index !== program.instructions.length - 1) {
    throw new Error("output must be the terminal instruction");
  }
  return program;
}

// Owner-side reference only; it is not the encrypted evaluator or detector.
export function evaluateCircuitReference(program, inputValues) {
  validateCircuit(program);
  if (!Array.isArray(inputValues) || inputValues.length !== program.inputs.length) throw new Error("input count mismatch");
  const inputs = inputValues.map(value => {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed >= 1n << 64n) throw new Error("input out of range");
    return parsed;
  });
  const outputs = [];
  const resolve = ref => ref.kind === "constant" ? BigInt(ref.value)
    : ref.kind === "input" ? inputs[ref.index] : outputs[ref.index];
  for (const instruction of program.instructions) {
    const result = evaluateLeaf(instruction.opcode, resolve(instruction.lhs), resolve(instruction.rhs));
    if (!result.valid) throw new Error(`invalid leaf ${instruction.index}: ${result.reason}`);
    outputs.push(result.value);
  }
  return { outputs, value: outputs[program.output.index] };
}
