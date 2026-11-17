import { ethers, buildAuthenticatedTracePlan, computeBoundResultHash, leafHash, traceLeafClaim } from "./evm-lib.mjs";
import { OPCODES } from "./micro-isa.mjs";
import { canonicalTrace, hashJson } from "./canonical-protocol.mjs";
export const CONTEXT_TYPES = { CanonicalContext: [
  { name: "taskId", type: "bytes32" }, { name: "contextDigest", type: "bytes32" }
] };
export const RESULT_TYPES = { CanonicalLeafResult: [
  { name: "profileDigest", type: "bytes32" }, { name: "contextDigest", type: "bytes32" },
  { name: "leafBinding", type: "bytes32" }, { name: "resultHandle", type: "bytes32" }
] };
export const FULL_TYPES = { FullCanonicalExecution: [
  {name:"taskId",type:"bytes32"},{name:"contextDigest",type:"bytes32"},
  {name:"traceRoot",type:"bytes32"},{name:"resultHash",type:"bytes32"}
] };
export function canonicalDomain(chainId, verifier) {
  return { name: "VCFHE-Canonical-Execution", version: "1", chainId, verifyingContract: verifier };
}
export function publicTracePlan(taskId, context, manifest) {
  const leaves = manifest.leaves.map(row => ({ opcode: OPCODES[row.opcode],
    lhs: row.lhs.kind === "constant" ? row.lhs.value : 0,
    rhs: row.rhs.kind === "constant" ? row.rhs.value : 0,
    claimed: 0, lhsRef: row.lhs, rhsRef: row.rhs,
    lhsHandle: row.lhsHandle, rhsHandle: row.rhsHandle, claimedHandle: row.resultHandle }));
  const handles = { leafResultHandles: manifest.leaves.map(r => r.resultHandle),
    inputHandle: (i, side) => manifest.leaves[i][`${side}Handle`],
    isPublicConstant: (i, side) => manifest.leaves[i][side].kind === "constant" };
  return { leaves, handles, plan: buildAuthenticatedTracePlan(taskId, leaves,
    context.inputs.map(r => r.owner), leaves, handles) };
}
export const outputArtifactDigest = (context, handle) => hashJson({
  kind: "canonical-output-artifact-v1", contextDigest: hashJson(context), terminalHandle: handle
});
// Authenticate only the isolated opening. A dishonest challenger need not
// provide a ciphertext preimage, or any other part of its candidate trace.
export async function checkCanonicalTerminal({ game, availability, taskId, leafIndex, operatorLeaf, challengerLeaf }) {
  if (!challengerLeaf || !Number.isInteger(challengerLeaf.opcode) ||
      challengerLeaf.opcode < 0 || challengerLeaf.opcode > 255 ||
      ["lhsHandle", "rhsHandle", "claimedHandle"].some(k => !/^0x[0-9a-fA-F]{64}$/.test(challengerLeaf[k])))
    throw new Error("malformed terminal opening");
  const state = await game.getTaskDisputeState(taskId);
  const pending = await game.getPendingFhevmLeafResolution(taskId);
  const status = await game.getTaskStatus(taskId);
  const op = traceLeafClaim(operatorLeaf), ch = traceLeafClaim(challengerLeaf);
  // Canonical admission sets only active; opcode/index below come from the
  // authenticated bisection state, not the unused legacy-FHEVM request fields.
  if (Number(status.status) !== 2 || !pending.active || Number(state.disputeEnd - state.disputeStart) !== 1 ||
      Number(state.disputeStart) !== leafIndex || !(await availability.isDisputeReady(taskId)))
    throw new Error("leaf not admitted on chain");
  if (leafHash(op) !== state.currentOperatorNode || leafHash(ch) !== state.currentChallengerNode ||
      op.opcode !== ch.opcode || op.lhsHandle !== ch.lhsHandle || op.rhsHandle !== ch.rhsHandle)
    throw new Error("uncommitted or inconsistent terminal opening");
  const disclosed = await availability.getDisclosedLeafHandles(taskId, leafIndex);
  if (disclosed.traceLeafHash !== leafHash(op) || disclosed.claimedHandle !== op.claimedHandle)
    throw new Error("disclosed terminal opening mismatch");
  return ch;
}
// Used independently by each signing worker and the final-output service.
export async function checkCanonicalTask({ game, availability, verifier, taskId, context, publicDir, operatorDir,
  requireRegistered = true }) {
  if (!(await game.secureTraceMode()) || await game.fhevmVerifier() !== ethers.ZeroAddress ||
      await game.kmsVerdictVerifier() !== ethers.ZeroAddress ||
      (await game.leafDecisionVerifier()).toLowerCase() !== verifier.target.toLowerCase() ||
      (await verifier.game()).toLowerCase() !== game.target.toLowerCase() ||
      await verifier.profileDigest() !== hashJson(context.profile)) throw new Error("wrong canonical deployment");
  const trace = await canonicalTrace(context, publicDir, operatorDir);
  const { plan, leaves } = publicTracePlan(taskId, context, trace.manifest);
  const auth = await availability.getTaskAuthorization(taskId);
  const binding = await game.getTaskResultBinding(taskId);
  const artifact = outputArtifactDigest(context, trace.manifest.terminalHandle);
  if (!auth.consumed || auth.traceRoot !== trace.tree.root || auth.inputRoot !== plan.inputTree.root ||
      auth.programRoot !== plan.programTree.root || auth.provenanceRoot !== plan.provenanceTree.root ||
      auth.outputAttestationHash !== artifact || Number(auth.leafCount) !== leaves.length ||
      binding.operatorTraceRoot !== trace.tree.root || Number(binding.leafCount) !== leaves.length ||
      binding.resultHash !== computeBoundResultHash(taskId, trace.tree.root, leaves.length, trace.manifest.terminalHandle, artifact)) throw new Error("task statement/context mismatch");
  if (requireRegistered && await verifier.contexts(taskId) !== hashJson(context)) throw new Error("context certificate mismatch");
  return trace;
}
export function canonicalFinalityAdapter({ game, availability, verifier, context, publicDir, operatorDir }) {
  return async request => {
    if (request.game.toLowerCase() !== game.target.toLowerCase() ||
        String((await game.runner.provider.getNetwork()).chainId) !== request.chainId) return null;
    const status = await game.getTaskStatus(request.taskId);
    if (Number(status.status) !== 3 || Number(status.decision) !== 1 || status.challengeTriggered ||
        !(await availability.isCleared(request.taskId))) return null;
    const trace = await checkCanonicalTask({ game, availability, verifier, taskId: request.taskId,
      context, publicDir, operatorDir });
    return { contextDigest: hashJson(context), programDigest: context.programDigest,
      outputDigest: trace.manifest.terminalHandle,
      recordIds: [...new Set(context.inputs.map(r => r.protectedId))],
      recordOwners: Object.fromEntries(context.inputs.map(r => [r.protectedId, r.owner.toLowerCase()])),
      outputType: BigInt(context.domain.outputBounds.at(-1).max) <= 1n ? "bool" : "uint64" };
  };
}
