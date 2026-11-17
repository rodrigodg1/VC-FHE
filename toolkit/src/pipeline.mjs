/**
 * One-call orchestrator: "tell the system what you want, it does the rest".
 *
 * `prepareComputation()` runs the complete front end and returns both the
 * result and a record of every stage it went through, so the flow is
 * self-documenting: the returned `steps` array is what the CLI prints and what
 * the documentation describes.
 *
 * Stages
 *   1 receive    accept the high-level request
 *   2 parse      syntax analysis into a structured expression
 *   3 classify   decide linear, non-linear, or unsupported
 *   4 validate   check operations, types, domain and limits
 *   5 lower      emit the low-level instructions (or the linear statement)
 *   6 bind       derive the on-chain statement (roots / constructor arguments)
 *   7 report     state what the deployer must still supply, and what runs next
 *
 * Nothing here changes the protocol: every stage delegates to the components
 * that already exist. A failure at any stage stops the pipeline and is
 * reported with the stage, the reason and, where useful, a suggestion.
 */
import { defineComputation, CompilationError, ExpressionError } from "./index.mjs";
import { buildDeploymentArtifact } from "./deployment.mjs";

/**
 * @param {string} request     the computation, e.g. "3*x1 + 2*x2 - x3"
 * @param {object} options
 *   inputs      concrete unsigned values, required for the non-linear pipeline
 *   taskLabel   human label used to derive the task identifier
 *   inputOwner  address credited as the origin of the input records
 *   datasetTag  dataset/epoch label recorded on-chain
 * @returns {Promise<object>} { ok, steps, task, artifact, nextActions, error }
 */
export async function prepareComputation(request, options = {}) {
  const steps = [];
  const t0 = Date.now();
  const step = (n, name, status, detail, data) => {
    steps.push({ n, name, status, detail, ...(data ? { data } : {}) });
    return steps[steps.length - 1];
  };

  step(1, "receive", "ok", `request accepted: "${request}"`);

  let task, artifact;
  try {
    // Stages 2 to 5 are performed by defineComputation, which parses,
    // classifies, validates and lowers in one pass.
    task = await defineComputation(request, options);

    step(2, "parse", "ok",
      `syntax accepted; ${task.variables.length} variable(s): ${task.variables.join(", ")}; depth ${task.depth}`);

    step(3, "classify", "ok",
      `pipeline = ${task.pipeline}${task.classification.operation ? ` (${task.classification.operation})` : ""}`,
      { reason: task.classification.reason });

    step(4, "validate", "ok",
      task.pipeline === "linear"
        ? "weight pattern matches an authorized deployment configuration"
        : "all operations are in the micro-ISA; values stay in the unsigned 64-bit domain");

    if (task.pipeline === "linear") {
      const a = task.deployment.constructorArgs;
      step(5, "lower", "ok",
        `no micro-trace needed; the statement is the authorized ${a.operationName} over ${a.totalItems} inputs`);
    } else {
      const t = task.trace;
      step(5, "lower", "ok",
        `${t.realInstructions} instruction(s) padded to ${t.leafCount} leaves; ` +
        `${t.bisectionRounds} bisection round(s) if challenged`,
        { instructions: t.witnesses.map((w) => `${w.opcode_name}(${w.lhs}, ${w.rhs}) = ${w.claimed}`) });
    }

    artifact = await buildDeploymentArtifact(task, options);

    if (artifact.pipeline === "linear") {
      step(6, "bind", "ok", `constructor arguments for ${artifact.contract}`,
        { constructorArgs: artifact.constructorArgs, taskId: artifact.taskId });
    } else {
      step(6, "bind", "ok", `authenticated task statement for ${artifact.contract}`,
        { taskId: artifact.taskId, ...artifact.statement });
    }
  } catch (err) {
    const isKnown = err instanceof CompilationError || err instanceof ExpressionError;
    const failed = steps.length + 1;
    step(failed, failed <= 2 ? "parse" : failed <= 4 ? "validate" : "lower", "rejected",
      err.message, { code: err.code ?? "E_ERROR", ...(err.hint ? { hint: err.hint } : {}) });
    return {
      ok: false,
      steps,
      error: { code: err.code ?? "E_ERROR", message: err.message, hint: err.hint ?? null, known: isKnown },
      elapsedMs: Date.now() - t0,
    };
  }

  // Stage 7: what the system cannot decide on the user's behalf.
  const nextActions = artifact.pipeline === "linear"
    ? [
        `deploy ${artifact.contract} with ${JSON.stringify(artifact.constructorArgs)}`,
        `enrol ${artifact.constructorArgsNamed.totalItems} owner address(es), one per index`,
        "each owner registers its key and admits its signed record",
        "the operator submits the result; the contract accepts it in constant cost",
        "the consumer recomputes the digest and commitment before decrypting",
      ]
    : [
        `deploy ${artifact.contract} and the leaf verifier`,
        "register the owner-origin ciphertext handles",
        `authorize the task with the three derived roots (taskId ${artifact.taskId.slice(0, 14)}...)`,
        "the operator commits the trace; auditors are sampled after the commitment",
        "absent a challenge the task finalizes optimistically",
        "on challenge, the trace is disclosed, bisected, and one instruction is re-executed on-chain",
      ];

  step(7, "report", "ok", `${nextActions.length} deployment action(s) remain`, { nextActions });

  return {
    ok: true, steps, task, artifact, nextActions,
    requires: artifact.requires,
    elapsedMs: Date.now() - t0,
  };
}

/** Render the recorded stages as readable text. */
export function renderSteps(result) {
  const L = [];
  for (const s of result.steps) {
    const mark = s.status === "ok" ? "OK " : "!! ";
    L.push(`${mark} step ${s.n}  ${s.name.padEnd(9)} ${s.detail}`);
    if (s.data?.reason) L.push(`                      reason: ${s.data.reason}`);
    if (s.data?.hint) L.push(`                      hint: ${s.data.hint}`);
    if (s.data?.instructions) {
      for (const i of s.data.instructions) L.push(`                        ${i}`);
    }
    if (s.data?.constructorArgs) L.push(`                      args: ${JSON.stringify(s.data.constructorArgs)}`);
    for (const k of ["inputRoot", "programRoot", "provenanceRoot"]) {
      if (s.data?.[k]) L.push(`                      ${k}: ${s.data[k]}`);
    }
    if (s.data?.nextActions) {
      s.data.nextActions.forEach((a, i) => L.push(`                      ${i + 1}. ${a}`));
    }
  }
  return L.join("\n");
}
