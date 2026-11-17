/**
 * Deployment artefact generation: the last step from a compiled expression to
 * something the contracts can actually consume, with nothing hard-coded.
 *
 * For the LINEAR pipeline the artefact is the constructor argument tuple of
 * MKLHSVerification. The authorized weight pattern is implied by
 * allowedOperation and is fixed at deployment, exactly as before.
 *
 * For the NON-LINEAR pipeline the artefact additionally contains the three
 * authenticated roots the task statement binds. Those roots are NOT recomputed
 * here: this module calls the production builder
 * `buildAuthenticatedTracePlan()` from fhe-pod/scripts/evm-lib.mjs, so the
 * roots are byte-identical to the ones the existing runners produce for a
 * hand-written trace.
 *
 * Nothing in this file changes the protocol. It only removes the manual step of
 * assembling the statement by hand.
 */
import path from "node:path";
import { createRequire } from "node:module";
import { VCFHE_ROOT } from "./compiler.mjs";

/**
 * Resolve ethers from the package that already depends on it, so the toolkit
 * adds no dependency of its own and always uses the same version as the
 * production tooling.
 */
let _ethers = null;
async function loadEthers() {
  if (_ethers) return _ethers;
  const anchor = path.join(VCFHE_ROOT, "fhe-pod", "scripts", "evm-lib.mjs");
  try {
    const req = createRequire(anchor);
    _ethers = req("ethers");
  } catch {
    _ethers = await import("ethers");
  }
  return _ethers.ethers ?? _ethers;
}

let _evmLib = null;
/** Lazily load the production EVM helper library. */
export async function productionEvmLib() {
  if (_evmLib) return _evmLib;
  const url = new URL(`file://${path.join(VCFHE_ROOT, "fhe-pod", "scripts", "evm-lib.mjs")}`);
  _evmLib = await import(url.href);
  return _evmLib;
}

/**
 * Build the complete, deployment-ready artefact for a compiled task.
 *
 * @param {object} task     result of defineComputation()
 * @param {object} options
 *   taskId      bytes32 task identifier (derived from the label when omitted)
 *   taskLabel   human label used to derive taskId
 *   inputOwner  address credited as the origin of the input records
 * @returns {object} artefact ready for deployment and task assignment
 */
export async function buildDeploymentArtifact(task, options = {}) {
  const ethers = await loadEthers();
  const label = options.taskLabel ?? `vcfhe-${task.pipeline}-task`;
  const taskId = options.taskId ?? ethers.keccak256(ethers.toUtf8Bytes(label));

  if (task.pipeline === "linear") {
    const a = task.deployment.constructorArgs;
    return {
      pipeline: "linear",
      expression: task.expression,
      taskId,
      contract: "MKLHSVerification",
      // Positional constructor arguments, in the contract's declared order.
      constructorArgs: [a.datasetRef, a.scale, a.totalItems, a.allowedOperation],
      constructorArgsNamed: {
        datasetRef: a.datasetRef, scale: a.scale,
        totalItems: a.totalItems, allowedOperation: a.allowedOperation,
        operationName: a.operationName,
      },
      requires: {
        owners: `${a.totalItems} enrolled owner addresses, one per index`,
        datasetTag: "non-zero bytes32 tag identifying dataset and epoch",
      },
      verification: "constant-cost accumulator equality; no dispute window",
    };
  }

  // ---- non-linear: derive the authenticated statement from the trace
  const inputOwner = options.inputOwner ?? ethers.ZeroAddress;
  const { buildAuthenticatedTracePlan } = await productionEvmLib();
  const plan = buildAuthenticatedTracePlan(taskId, task.trace.witnesses, inputOwner);

  return {
    pipeline: "non-linear",
    expression: task.expression,
    taskId,
    contract: "LegacyConfigurableDisputeGame",
    mode: "legacy-value-regression",
    statement: {
      inputRoot: plan.inputTree.root,
      programRoot: plan.programTree.root,
      provenanceRoot: plan.provenanceTree.root,
    },
    trace: {
      leafCount: task.trace.leafCount,
      realInstructions: task.trace.realInstructions,
      bisectionRounds: task.trace.bisectionRounds,
      witnesses: task.trace.witnesses,
    },
    inputRecords: plan.inputRecords,
    result: task.result,
    requires: {
      inputOwner: "address that registered the owner-origin ciphertext handles",
      operator: "assigned operator address",
      auditors: "auditor pool registered before the trace commitment",
    },
    verification: "optimistic finality; on challenge, bisection to one instruction resolved on-chain",
  };
}

/**
 * Convenience: expression string -> deployment-ready artefact in one call.
 */
export async function compileToDeployment(expression, options = {}) {
  const { defineComputation } = await import("./index.mjs");
  const task = await defineComputation(expression, options);
  const artifact = await buildDeploymentArtifact(task, options);
  return { task, artifact };
}
