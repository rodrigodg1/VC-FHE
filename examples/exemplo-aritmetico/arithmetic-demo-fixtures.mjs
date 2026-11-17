/**
 * Inputs of the minimal arithmetic teaching example: total = x + y * z.
 *
 * There is no dataset and no scenario here on purpose. The example exists to
 * show the PROCESS a computation goes through, on the shortest trace that still
 * passes through every stage of it, so the three values are arbitrary and are
 * declared as such.
 *
 * EVERY value here is encrypted. This expression has no public scalar, because
 * it has no DIV: the four opcodes that take a cleartext right operand (DIV, MOD,
 * SHR, ADD_CHAIN) are all absent. See ../../Anatel/anatel-rqual-simplificado/ for a trace
 * that exercises that rule.
 *
 * The validation below is not ceremony. Each check corresponds to a rule the
 * micro-ISA enforces later, and catching a violation here means the run fails
 * with a sentence a reader can act on instead of with a rejected leaf.
 *
 * Imports nothing beyond node builtins on purpose: the example must be
 * buildable and printable without installing the Node dependency tree.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

export const ARITHMETIC_PARAMS_JSON = path.join(scriptDir, "arithmetic-demo-params.json");

function readJson(filePath, label) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`${label}: cannot read ${filePath} (${error.message})`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${label}: ${filePath} is not valid JSON (${error.message})`);
  }
}

/**
 * Unwraps one declared value.
 *
 * The parameter file stores `{value, _note, _source}` rather than a bare number
 * so that no value can travel through the pipeline without the note saying what
 * it is. Here the answer is always "arbitrary", and saying so next to each
 * number is cheaper than saying it once in a preface a reader may skip.
 */
function param(params, key) {
  const entry = params?.[key];
  if (!entry || typeof entry !== "object" || !("value" in entry)) {
    throw new Error(
      `arithmetic-demo-params.json is missing parameter "${key}" (expected an object with a "value" field)`
    );
  }
  if (typeof entry._note !== "string" || entry._note.length === 0) {
    throw new Error(`arithmetic-demo-params.json parameter "${key}" carries no _note`);
  }
  return entry.value;
}

function assertNonNegativeInteger(value, label) {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(
      `${label} must be a non-negative integer: the micro-ISA is unsigned 64-bit integer ` +
        `arithmetic and has no representation for anything else; received ${String(value)}`
    );
  }
  return value;
}

/** Loads the declared values and checks every rule the trace depends on. */
export function loadArithmeticParams() {
  const raw = readJson(ARITHMETIC_PARAMS_JSON, "arithmetic teaching example parameters");
  if (typeof raw._disclaimer !== "string" || raw._disclaimer.length === 0) {
    throw new Error("arithmetic-demo-params.json must carry a top-level _disclaimer");
  }

  const x = assertNonNegativeInteger(param(raw, "x"), "x");
  const y = assertNonNegativeInteger(param(raw, "y"), "y");
  const z = assertNonNegativeInteger(param(raw, "z"), "z");

  // MUL and ADD both reject a result above 2^64-1, and the lowering would fail
  // at the offending leaf. Checking here means the error names the parameter
  // rather than the leaf it eventually broke.
  const U64_MAX = 2n ** 64n - 1n;
  if (BigInt(y) * BigInt(z) > U64_MAX) {
    throw new Error(`y * z overflows uint64 (${y} * ${z}); MUL would be rejected by the objective verifier`);
  }
  if (BigInt(y) * BigInt(z) + BigInt(x) > U64_MAX) {
    throw new Error(`x + y * z overflows uint64; ADD would be rejected by the objective verifier`);
  }

  return {
    disclaimer: raw._disclaimer,
    expression: raw._expression ?? null,
    precedence: raw._precedence ?? null,
    whyThisShape: raw._whyThisShape ?? null,
    whatIsNotHere: raw._whatIsNotHere ?? null,
    x,
    y,
    z,
    notes: Object.fromEntries(
      Object.entries(raw)
        .filter(([key, entry]) => !key.startsWith("_") && entry && typeof entry === "object")
        .map(([key, entry]) => [key, { _note: entry._note, ...(entry._source ? { _source: entry._source } : {}) }])
    )
  };
}

/**
 * The inputs of one run, with the role of each value stated explicitly.
 *
 * `role` is the field worth reading: here it is "encrypted operand" for all
 * three, without exception. An expression that used DIV, MOD, SHR or ADD_CHAIN
 * would have one value declared as a public scalar instead, and that distinction
 * is what the whole privacy argument rests on.
 */
export function arithmeticInputs() {
  const params = loadArithmeticParams();

  const provenance = {
    disclaimer: params.disclaimer,
    expression: params.expression,
    everyInputDeclared: true,
    everyInputMeasured: false,
    x: { role: "encrypted operand", measured: false, source: "ARBITRARY value declared for this example" },
    y: { role: "encrypted operand", measured: false, source: "ARBITRARY value declared for this example" },
    z: { role: "encrypted operand", measured: false, source: "ARBITRARY value declared for this example" },
    everyOperandEncrypted: true
  };

  return {
    x: params.x,
    y: params.y,
    z: params.z,
    params,
    provenance
  };
}
