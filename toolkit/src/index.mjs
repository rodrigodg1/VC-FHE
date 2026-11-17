/**
 * Public interface of the toolkit.
 *
 * This is a thin, additive access layer over the existing implementation. It
 * does not modify the protocol, the contracts or the experiments: it only makes
 * the supported computations easier to express, inspect and hand to the
 * components that are already there.
 *
 * Typical use:
 *
 *   import { defineComputation } from "./src/index.mjs";
 *
 *   const task = await defineComputation("x1 + x2 + x3");            // linear
 *   const task = await defineComputation("3*x1 + 2*x2 - x3",         // non-linear
 *                                        { inputs: { x1: 4, x2: 5, x3: 2 } });
 *   task.pipeline        // "linear" | "non-linear"
 *   task.explain()       // human-readable classification and instruction list
 *   task.toConfig()      // JSON consumed by deployment / task assignment
 */
import { compileExpression, classify, CompilationError, LIMITS } from "./compiler.mjs";
import { parse, collectVariables, depth, ExpressionError, BINARY_CALLS, UNARY_CALLS, INFIX_OPS } from "./parser.mjs";

export { CompilationError, ExpressionError, LIMITS, classify, parse, collectVariables, depth };
export { buildDeploymentArtifact, compileToDeployment } from "./deployment.mjs";
export { prepareComputation, renderSteps } from "./pipeline.mjs";

/** Operations the toolkit can express, grouped by how they are verified. */
export const SUPPORTED_OPERATIONS = Object.freeze({
  linearPipeline: ["sum of distinct variables (weights +1)", "first-positive difference (weights +1,-1,...)"],
  microISA: {
    infix: { ...INFIX_OPS },
    binaryCalls: { ...BINARY_CALLS },
    unaryCalls: { ...UNARY_CALLS },
  },
});

/**
 * Compile a high-level expression into a task definition.
 * Throws ExpressionError for malformed input and CompilationError for input
 * that is well-formed but outside what the protocol can verify.
 */
export async function defineComputation(expression, options = {}) {
  const compiled = await compileExpression(expression, options);

  return {
    ...compiled,

    /** Human-readable summary for inspection before any deployment. */
    explain() {
      const L = [];
      L.push(`expression : ${compiled.expression}`);
      L.push(`variables  : ${compiled.variables.join(", ")}`);
      L.push(`pipeline   : ${compiled.pipeline}`);
      L.push(`reason     : ${compiled.classification.reason}`);
      if (compiled.classification.forced) {
        L.push("note       : pipeline was forced by the caller and differs from the classification");
      }
      if (compiled.pipeline === "linear") {
        const a = compiled.deployment.constructorArgs;
        L.push(`operation  : ${a.operationName} (allowedOperation=${a.allowedOperation}, totalItems=${a.totalItems})`);
        L.push("verified by: constant-cost accumulator equality, no dispute window");
      } else {
        const t = compiled.trace;
        L.push(`result     : ${compiled.result}`);
        L.push(`trace      : ${t.realInstructions} instructions padded to ${t.leafCount} leaves ` +
               `(${t.paddingLeaves} padding), ${t.bisectionRounds} bisection rounds`);
        L.push("instructions:");
        for (const w of t.witnesses) {
          const tail = w.note === "padding no-op" ? "  [padding]" : "";
          L.push(`  #${String(w.leaf_index).padStart(3)}  ${w.opcode_name.padEnd(8)} ` +
                 `lhs=${w.lhs}  rhs=${w.rhs}  =>  ${w.claimed}${tail}`);
        }
      }
      return L.join("\n");
    },

    /** Configuration object consumed by deployment and task assignment. */
    toConfig() {
      const base = {
        toolkitVersion: "1.0.0",
        expression: compiled.expression,
        variables: compiled.variables,
        pipeline: compiled.pipeline,
        classification: compiled.classification,
        deployment: compiled.deployment,
      };
      if (compiled.pipeline === "non-linear") {
        base.trace = {
          leafCount: compiled.trace.leafCount,
          realInstructions: compiled.trace.realInstructions,
          bisectionRounds: compiled.trace.bisectionRounds,
          witnesses: compiled.trace.witnesses,
        };
        base.result = compiled.result;
      }
      return base;
    },
  };
}

/**
 * Classify without compiling. Useful to check whether an expression is
 * supported, and by which pipeline, before supplying inputs.
 */
export function inspectExpression(expression) {
  const ast = parse(expression);
  const vars = collectVariables(ast);
  const d = classify(ast, { variables: vars });
  return {
    expression, variables: vars, depth: depth(ast),
    pipeline: d.pipeline, operation: d.operation ?? null, reason: d.reason,
  };
}
