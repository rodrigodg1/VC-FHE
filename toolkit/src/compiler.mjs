/**
 * Classification, validation and lowering.
 *
 * Pipeline selection is decided by what the deployed contracts can actually
 * verify, not by what "looks" linear:
 *
 *   LINEAR pipeline (deterministic, O(1) on-chain check)
 *     The contract fixes the authorized weight pattern at deployment and
 *     supports exactly two of them:
 *        SUM : x_0 + x_1 + ... + x_{n-1}          (all weights +1)
 *        SUB : x_0 - x_1 - ... - x_{n-1}          (w_0 = +1, others -1)
 *     An expression qualifies only if it is a sum of DISTINCT declared
 *     variables, each appearing exactly once, matching one of those patterns.
 *
 *   NON-LINEAR pipeline (optimistic, audited micro-trace)
 *     Everything else that is expressible in the micro-ISA, including linear
 *     expressions with coefficients other than +1/-1 (for example 3*x1 + 2*x2),
 *     which the linear contract cannot verify but which lower perfectly well to
 *     a MUL/ADD trace.
 *
 *   REJECTED
 *     Unsupported operators or functions, non-integer or negative literals,
 *     computations whose intermediate values leave the unsigned domain, and
 *     expressions exceeding the configured size limits.
 *
 * The lowering reuses the production `leaf()` and `OPCODES` from
 * fhe-pod/scripts/application-lowering.mjs, so generated instructions are
 * structurally identical to hand-written ones by construction.
 */
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse, collectVariables, depth, ExpressionError, INFIX_OPS } from "./parser.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

/** Repository root (VC-FHE). Override with VCFHE_ROOT when used out of tree. */
export const VCFHE_ROOT = process.env.VCFHE_ROOT
  ? path.resolve(process.env.VCFHE_ROOT)
  : path.resolve(__dirname, "..", "..");

let _production = null;
/** Load the production lowering module (leaf, OPCODES) lazily. */
export async function productionLowering() {
  if (_production) return _production;
  const url = new URL(`file://${path.join(VCFHE_ROOT, "fhe-pod", "scripts", "application-lowering.mjs")}`);
  _production = await import(url.href);
  return _production;
}

export const LIMITS = Object.freeze({
  MAX_VARIABLES: 64,
  MAX_DEPTH: 32,
  MAX_LEAVES: 1024,          // power-of-two padded trace length
  MAX_UINT: (1n << 64n) - 1n, // unsigned 64-bit domain of the micro-ISA
});

export class CompilationError extends Error {
  constructor(message, { code = "E_REJECTED", hint = null, detail = null } = {}) {
    super(message);
    this.name = "CompilationError";
    this.code = code;
    this.hint = hint;
    this.detail = detail;
  }
}

/**
 * Try to read the AST as a plain weighted sum of variables.
 * Returns a Map name -> integer coefficient, or null when the expression is not
 * an affine combination of variables (for example when it contains a product of
 * two variables or a comparison).
 */
export function affineForm(ast) {
  const out = new Map();
  let constant = 0n;
  let ok = true;

  function add(name, coef) {
    if (name === null) { constant += coef; return; }
    out.set(name, (out.get(name) ?? 0n) + coef);
  }
  function walk(node, sign) {
    if (!ok) return;
    switch (node.kind) {
      case "num": add(null, sign * node.value); return;
      case "var": add(node.name, sign); return;
      case "neg": walk(node.operand, -sign); return;
      case "bin": {
        if (node.op === "+") { walk(node.left, sign); walk(node.right, sign); return; }
        if (node.op === "-") { walk(node.left, sign); walk(node.right, -sign); return; }
        if (node.op === "*") {
          // constant * variable-part is affine; variable * variable is not
          const l = constFold(node.left), r = constFold(node.right);
          if (l !== null && r !== null) { add(null, sign * l * r); return; }
          if (l !== null) { scaled(node.right, sign * l); return; }
          if (r !== null) { scaled(node.left, sign * r); return; }
          ok = false; return;
        }
        ok = false; return; // '/' and '%' are not affine
      }
      default: ok = false;
    }
  }
  function scaled(node, factor) {
    if (!ok) return;
    switch (node.kind) {
      case "num": add(null, factor * node.value); return;
      case "var": add(node.name, factor); return;
      case "neg": scaled(node.operand, -factor); return;
      case "bin": {
        if (node.op === "+") { scaled(node.left, factor); scaled(node.right, factor); return; }
        if (node.op === "-") { scaled(node.left, factor); scaled(node.right, -factor); return; }
        if (node.op === "*") {
          const l = constFold(node.left), r = constFold(node.right);
          if (l !== null) { scaled(node.right, factor * l); return; }
          if (r !== null) { scaled(node.left, factor * r); return; }
          ok = false; return;
        }
        ok = false; return;
      }
      default: ok = false;
    }
  }
  function constFold(node) {
    if (node.kind === "num") return node.value;
    if (node.kind === "neg") { const v = constFold(node.operand); return v === null ? null : -v; }
    if (node.kind === "bin") {
      const l = constFold(node.left), r = constFold(node.right);
      if (l === null || r === null) return null;
      if (node.op === "+") return l + r;
      if (node.op === "-") return l - r;
      if (node.op === "*") return l * r;
      if (node.op === "/") return r === 0n ? null : l / r;
      if (node.op === "%") return r === 0n ? null : l % r;
    }
    return null;
  }

  walk(ast, 1n);
  return ok ? { coefficients: out, constant } : null;
}

/** Decide the pipeline and explain the decision. */
export function classify(ast, { variables } = {}) {
  const vars = variables ?? collectVariables(ast);
  const affine = affineForm(ast);

  if (!affine) {
    return { pipeline: "non-linear", reason: "expression contains a non-affine operation (product of variables, division, modulo or a predicate)", affine: null, vars };
  }
  const coeffs = affine.coefficients;
  const allVarsCovered = vars.length > 0 && vars.every((v) => coeffs.has(v));
  const values = vars.map((v) => coeffs.get(v) ?? 0n);
  const hasConstant = affine.constant !== 0n;

  const isSum = !hasConstant && allVarsCovered && values.every((c) => c === 1n);
  const isSub = !hasConstant && allVarsCovered && values[0] === 1n && values.slice(1).every((c) => c === -1n);

  if (isSum) {
    return { pipeline: "linear", operation: "SUM", allowedOperation: 0,
      reason: "sum of distinct variables with all weights +1, which the linear contract verifies deterministically", affine, vars };
  }
  if (isSub) {
    return { pipeline: "linear", operation: "SUB", allowedOperation: 1,
      reason: "first variable positive and the remaining ones negative, matching the SUB weight pattern", affine, vars };
  }
  return {
    pipeline: "non-linear", affine, vars,
    reason: hasConstant
      ? "affine expression with a constant term; the linear contract fixes weights at deployment and admits no constant offset"
      : "affine expression whose coefficients are not the SUM (+1) or SUB (+1,-1,...) pattern fixed by the linear contract",
  };
}

/** Evaluate the AST over concrete unsigned inputs, enforcing the unsigned domain. */
function evaluate(node, env, trail) {
  const chk = (v, what) => {
    if (v < 0n) {
      throw new CompilationError(
        `intermediate value became negative while computing ${what}`,
        { code: "E_NEGATIVE_INTERMEDIATE",
          hint: "the micro-ISA is unsigned 64-bit; reorder the expression or choose inputs that keep every intermediate non-negative" });
    }
    if (v > LIMITS.MAX_UINT) {
      throw new CompilationError(`intermediate value overflowed the unsigned 64-bit domain while computing ${what}`,
        { code: "E_OVERFLOW" });
    }
    return v;
  };
  switch (node.kind) {
    case "num": return chk(node.value, "a literal");
    case "var": {
      if (!(node.name in env)) {
        throw new CompilationError(`no input value supplied for variable "${node.name}"`, { code: "E_MISSING_INPUT" });
      }
      return chk(BigInt(env[node.name]), `variable ${node.name}`);
    }
    case "neg": {
      const v = evaluate(node.operand, env, trail);
      return chk(-v, "a negation");
    }
    case "bin": {
      const l = evaluate(node.left, env, trail);
      const r = evaluate(node.right, env, trail);
      let v;
      switch (node.op) {
        case "+": v = l + r; break;
        case "-": v = l - r; break;
        case "*": v = l * r; break;
        case "/":
          if (r === 0n) throw new CompilationError("division by zero", { code: "E_DIV_ZERO" });
          v = l / r; break;
        case "%":
          if (r === 0n) throw new CompilationError("modulo by zero", { code: "E_DIV_ZERO" });
          v = l % r; break;
        default: throw new CompilationError(`unsupported operator ${node.op}`, { code: "E_UNSUPPORTED_OP" });
      }
      chk(v, `"${node.op}"`);
      trail.push({ opcode: INFIX_OPS[node.op], lhs: l, rhs: r, claimed: v, note: `${node.op}` });
      return v;
    }
    case "call": {
      const a = evaluate(node.args[0], env, trail);
      if (node.opcode === "CAST_U8") {
        const v = a % 256n;
        trail.push({ opcode: "CAST_U8", lhs: a, rhs: 0n, claimed: v, note: "cast_u8" });
        return v;
      }
      const b = evaluate(node.args[1], env, trail);
      let v;
      switch (node.opcode) {
        case "MIN": v = a < b ? a : b; break;
        case "EQ": v = a === b ? 1n : 0n; break;
        case "LT": v = a < b ? 1n : 0n; break;
        case "GT": v = a > b ? 1n : 0n; break;
        case "BITAND": v = a & b; break;
        case "BITOR": v = a | b; break;
        case "BITXOR": v = a ^ b; break;
        case "SHR":
          if (b > 63n) throw new CompilationError("shift amount must be at most 63", { code: "E_SHIFT_RANGE" });
          v = a >> b; break;
        default: throw new CompilationError(`unsupported call ${node.name}`, { code: "E_UNSUPPORTED_OP" });
      }
      chk(v, `${node.name}()`);
      trail.push({ opcode: node.opcode, lhs: a, rhs: b, claimed: v, note: node.name });
      return v;
    }
    default:
      throw new CompilationError(`unsupported node ${node.kind}`, { code: "E_UNSUPPORTED_OP" });
  }
}

function nextPowerOfTwo(n) { let p = 1; while (p < n) p <<= 1; return p; }

/**
 * Compile an expression into an artefact that the existing contracts consume.
 *
 * @param {string} expression   e.g. "3*x1 + 2*x2 - x3"
 * @param {object} options
 *   inputs      {x1: 5, ...}   concrete unsigned values (required for non-linear)
 *   variables   explicit variable order (defaults to order of appearance)
 *   datasetTag  label recorded on-chain
 *   forcePipeline "linear" | "non-linear" to override the classifier
 */
export async function compileExpression(expression, options = {}) {
  const ast = parse(expression);
  const vars = options.variables ?? collectVariables(ast);

  if (vars.length === 0) {
    throw new CompilationError("expression contains no variables", { code: "E_NO_VARIABLES" });
  }
  if (vars.length > LIMITS.MAX_VARIABLES) {
    throw new CompilationError(`expression uses ${vars.length} variables, limit is ${LIMITS.MAX_VARIABLES}`, { code: "E_TOO_MANY_VARIABLES" });
  }
  const d = depth(ast);
  if (d > LIMITS.MAX_DEPTH) {
    throw new CompilationError(`expression depth ${d} exceeds the limit of ${LIMITS.MAX_DEPTH}`, { code: "E_TOO_DEEP" });
  }

  const decision = classify(ast, { variables: vars });
  const pipeline = options.forcePipeline ?? decision.pipeline;

  const common = {
    expression,
    variables: vars,
    depth: d,
    classification: {
      pipeline: decision.pipeline,
      operation: decision.operation ?? null,
      reason: decision.reason,
      forced: Boolean(options.forcePipeline) && options.forcePipeline !== decision.pipeline,
    },
  };

  if (pipeline === "linear") {
    if (decision.pipeline !== "linear") {
      throw new CompilationError(
        `expression cannot be verified by the linear pipeline: ${decision.reason}`,
        { code: "E_NOT_LINEAR_VERIFIABLE",
          hint: "the linear contract fixes the weight pattern at deployment (SUM or SUB); use the non-linear pipeline for other coefficients" });
    }
    return {
      ...common,
      pipeline: "linear",
      deployment: {
        contract: "MKLHSVerification",
        constructorArgs: {
          datasetRef: options.datasetTag ?? "toolkit-task",
          scale: options.scale ?? 1,
          totalItems: vars.length,
          allowedOperation: decision.allowedOperation,
          operationName: decision.operation,
        },
        note: "weights are implied by allowedOperation and are fixed at deployment",
      },
    };
  }

  // ---- non-linear: lower to a micro-trace
  if (!options.inputs) {
    throw new CompilationError(
      "the non-linear pipeline needs concrete input values to emit the claimed value of each instruction",
      { code: "E_MISSING_INPUTS", hint: "pass options.inputs, for example { x1: 3, x2: 4 }" });
  }
  for (const v of vars) {
    if (!(v in options.inputs)) {
      throw new CompilationError(`missing input value for variable "${v}"`, { code: "E_MISSING_INPUT" });
    }
    const val = BigInt(options.inputs[v]);
    if (val < 0n) {
      throw new CompilationError(`input "${v}" is negative; the micro-ISA is unsigned`, { code: "E_NEGATIVE_INPUT" });
    }
  }

  const trail = [];
  const result = evaluate(ast, options.inputs, trail);
  if (trail.length === 0) {
    throw new CompilationError("expression reduces to a single value and produces no instruction to verify",
      { code: "E_TRIVIAL", hint: "a verifiable trace needs at least one operation" });
  }
  const padded = nextPowerOfTwo(trail.length);
  if (padded > LIMITS.MAX_LEAVES) {
    throw new CompilationError(`trace needs ${padded} leaves, limit is ${LIMITS.MAX_LEAVES}`, { code: "E_TRACE_TOO_LONG" });
  }

  const { leaf } = await productionLowering();
  const witnesses = trail.map((t, i) =>
    leaf(i, t.opcode, Number(t.lhs), Number(t.rhs), Number(t.claimed), `${t.note}`));
  for (let i = trail.length; i < padded; i++) {
    witnesses.push(leaf(i, "ADD", 0, 0, 0, "padding no-op"));
  }

  return {
    ...common,
    pipeline: "non-linear",
    result: Number(result),
    trace: {
      leafCount: padded,
      realInstructions: trail.length,
      paddingLeaves: padded - trail.length,
      bisectionRounds: Math.ceil(Math.log2(padded)),
      witnesses,
    },
    deployment: {
      contract: "LegacyConfigurableDisputeGame",
      mode: "legacy-value-regression",
      datasetRef: options.datasetTag ?? "toolkit-task",
      note: "trace, program and output roots are derived from the witnesses by the existing task-authorization tooling",
    },
  };
}
