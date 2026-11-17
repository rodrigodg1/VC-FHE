// Public interval admission: no plaintext or decryption oracle is consulted.
import { validateCircuit } from "./compliance-circuit.mjs";
export const UINT64_MAX = (1n << 64n) - 1n;
const integer = v => {
  if (!(typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v))) throw new Error("noncanonical integer bound");
  const n = BigInt(v); if (n > UINT64_MAX) throw new Error("bound outside uint64"); return n;
};
const min = (a, b) => a < b ? a : b, max = (a, b) => a > b ? a : b;
export function admitCanonicalDomain(program, bounds) {
  validateCircuit(program);
  if (!Array.isArray(bounds) || bounds.length !== program.inputs.length) throw new Error("missing input bounds");
  const inputs = bounds.map(b => {
    const lo = integer(b.min), hi = integer(b.max);
    if (lo > hi) throw new Error("reversed input bounds"); return [lo, hi];
  });
  const outputs = [], resolve = ref => ref.kind === "constant" ? [integer(ref.value), integer(ref.value)]
    : ref.kind === "input" ? inputs[ref.index] : outputs[ref.index];
  for (const op of program.instructions) {
    const [a, A] = resolve(op.lhs), [b, B] = resolve(op.rhs);
    let range;
    switch (op.opcode) {
      case "ADD": range = [a + b, A + B]; break;
      case "SUB":
        if (a < B) throw new Error(`possible underflow at ${op.index}`);
        range = [a - B, A - b]; break;
      case "MUL": range = [a * b, A * B]; break;
      case "DIV": case "MOD":
        if (b === 0n || b !== B) throw new Error(`invalid public divisor at ${op.index}`);
        range = op.opcode === "DIV" ? [a / b, A / b] : [0n, min(A, b - 1n)]; break;
      case "SHR":
        if (b !== B || b >= 64n) throw new Error(`invalid public shift at ${op.index}`);
        range = [a >> b, A >> b]; break;
      case "ADD_CHAIN":
        if (b !== B || b < 1n || b > 8n) throw new Error(`invalid public chain at ${op.index}`);
        range = [a + b, A + b]; break;
      case "EQ": case "GT": case "LT": range = [0n, 1n]; break;
      case "MIN": range = [min(a, b), min(A, B)]; break;
      case "BITAND": range = [0n, min(A, B)]; break;
      case "BITOR": case "BITXOR":
        range = [0n, (1n << BigInt(max(A, B).toString(2).length)) - 1n]; break;
      case "CAST_U8": range = A < 256n ? [a, A] : [0n, 255n]; break;
      default: throw new Error(`unsupported operation ${op.opcode}`);
    }
    if (range[1] > UINT64_MAX) throw new Error(`possible overflow at ${op.index}`);
    outputs.push(range);
  }
  return { version: "public-interval-admission-v1", inputBounds: bounds,
    outputBounds: outputs.map(([lo, hi]) => ({ min: String(lo), max: String(hi) })),
    assumption: "owners honestly encrypt records within their authenticated public bounds" };
}
