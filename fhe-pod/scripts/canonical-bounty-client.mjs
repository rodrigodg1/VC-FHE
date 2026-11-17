// Client for the separately versioned challenger-bounty game. This module does
// not replace the measured canonical campaign or perform the auditor's replay.
// Callers supply the operator trace and their independently obtained trace.
import { ethers, compileContracts, boundCreateTaskArgs, terminalOutputBinding,
  authorizeAuthenticatedTask, sampleTaskParticipants, buildAuditTranscript,
  challengeErrorDigest, leafHash, buildMerkleTree, selectAuditDiligenceCheckpoint,
  getSubtreeChildren, traceLeafClaim } from './evm-lib.mjs';
import { fileURLToPath } from 'node:url';
import { canonicalDomain, CONTEXT_TYPES, RESULT_TYPES } from './canonical-chain.mjs';

const confirm = async promise => (await promise).wait();
// The protocol permits 64 rows. Keep each relay transaction below its fixed
// 20-million gas budget by sending smaller authenticated prefixes.
export function bountyRelayBatchSize(requested) {
  if (!Number.isSafeInteger(requested) || requested < 1 || requested > 64)
    throw new Error('disclosure batch size must be in [1,64]');
  return Math.min(requested, 48);
}
export const sealedBountyAuditTypehash = ethers.id(
  'FHE_BOUNTY_AUDIT_V2(uint256 chainId,address game,bytes32 taskId,address auditor,uint32 leafIndex,bytes32 podRoot,bytes32 candidateTraceRoot,bool supportsOperator,bytes32 salt)');
export function sealedBountyAuditCommitment(chainId, gameAddress, opening) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'uint256', 'address', 'bytes32', 'address', 'uint32', 'bytes32', 'bytes32', 'bool', 'bytes32'],
    [sealedBountyAuditTypehash, chainId, gameAddress, ...opening]));
}

export async function deployCanonicalBountyStack({ requester, committee, profileDigest,
  windowSeconds = 20, operatorPenaltyWei = ethers.parseEther('1'),
  bountyWei = ethers.parseEther('0.25'), maxTraceLeaves = 8,
  challengeCostBudgetWei = ethers.parseEther('0.1'), artifacts }) {
  artifacts ??= await compileContracts();
  const deploy = async (name, args = []) => {
    const contract = await new ethers.ContractFactory(artifacts[name].abi,
      artifacts[name].bytecode, requester).deploy(...args);
    await contract.waitForDeployment(); return contract;
  };
  const objective = await deploy('ObjectiveMicroVerifier');
  const nonce = BigInt(await requester.provider.send('eth_getTransactionCount', [requester.address, 'pending']));
  const gameAddress = ethers.getCreateAddress({ from: requester.address, nonce: nonce + 2n });
  const availability = await deploy('BountyTraceAvailability', [gameAddress, windowSeconds]);
  const verifier = await deploy('CanonicalLeafVerifier', [gameAddress, profileDigest, committee, 2]);
  const game = await deploy('CanonicalBountyFHEDisputeGame', [objective.target, windowSeconds,
    windowSeconds, windowSeconds, availability.target, verifier.target, operatorPenaltyWei, bountyWei,
    maxTraceLeaves, challengeCostBudgetWei]);
  if (game.target !== gameAddress) throw new Error('predicted game address mismatch');
  return { game, availability, verifier, objective, artifacts };
}

export async function createBountyTask({ game, availability, requester, operator,
  taskId, operatorLeaves, outputAttestationHash = ethers.id('local-bounty-output') }) {
  const operatorTree = buildMerkleTree(operatorLeaves);
  const binding = terminalOutputBinding(taskId, operatorTree, operatorLeaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({ availability, requester, operatorAddress: operator.address,
    taskId, tree: operatorTree, leaves: operatorLeaves, resultHash: binding.resultHash, outputAttestationHash });
  await confirm(game.connect(operator).createTask(...boundCreateTaskArgs(taskId,
    operatorTree, operatorLeaves, outputAttestationHash)));
  await sampleTaskParticipants(game, taskId);
  return { taskId, operatorTree, operatorLeaves, plan };
}

// Keep this returned object private until ALL commitments are closed. In
// particular, publishing its index or transcript during commitment defeats
// the purpose of the sealed interface. The salt is generated with a CSPRNG.
export async function prepareSealedBountyAudit({ game, taskId, auditorAddress,
  operatorLeaves, candidateLeaves, index, supportsOperator = false,
  salt = ethers.hexlify(ethers.randomBytes(32)) }) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= operatorLeaves.length ||
      candidateLeaves.length !== operatorLeaves.length) throw new Error('invalid audit trace/index');
  const operatorTree = buildMerkleTree(operatorLeaves), candidateTree = buildMerkleTree(candidateLeaves);
  if (!ethers.isHexString(salt, 32) || salt === ethers.ZeroHash) throw new Error('a nonzero secret 32-byte salt is required');
  if (supportsOperator !== (candidateTree.root === operatorTree.root)) throw new Error('opinion contradicts candidate trace root');
  const errorDigest = challengeErrorDigest(taskId, index, operatorLeaves[index], candidateLeaves[index]);
  const transcript = buildAuditTranscript({ taskId, auditorAddress, operatorTraceRoot: operatorTree.root,
    auditTraceLeaf: { leafIndex: index, operatorLeafHash: leafHash(operatorLeaves[index]),
      recomputedLeafHash: leafHash(candidateLeaves[index]), errorDigest },
    operatorLeaf: operatorLeaves[index], recomputedLeaf: candidateLeaves[index] });
  const opening = [taskId, auditorAddress, index, transcript.root, candidateTree.root, supportsOperator, salt];
  // Hash locally: sending the opening to a view function would disclose the
  // still-secret fault index and salt to the RPC provider before commitment.
  const chainId = (await game.runner.provider.getNetwork()).chainId;
  const commitment = sealedBountyAuditCommitment(chainId, await game.getAddress(), opening);
  return { taskId, auditorAddress, index, supportsOperator, salt, errorDigest, transcript,
    operatorTree, candidateTree, operatorLeaves, candidateLeaves, opening, commitment };
}

export async function commitSealedBountyAudit(game, auditor, audit) {
  if (auditor.address.toLowerCase() !== audit.auditorAddress.toLowerCase())
    throw new Error('auditor identity differs from sealed opening');
  return confirm(game.connect(auditor).submitSealedAudit(audit.taskId, audit.commitment));
}

// Anyone can relay the opening; identity remains bound to the earlier commit.
export async function revealSealedBountyAudit(game, relayer, audit) {
  return confirm(game.connect(relayer).revealSealedAudit(...audit.opening, { gasLimit: 5_000_000 }));
}

export async function proveAndOpenBountyChallenge(game, auditor, audit) {
  if ((await game.getChallengeClaim(audit.taskId)).diligenceSeed === ethers.ZeroHash)
    await confirm(game.sealDiligenceRandomness(audit.taskId));
  const selected = selectAuditDiligenceCheckpoint(audit.transcript,
    await game.getRequiredDiligenceCheckpointIndex(audit.taskId, audit.auditorAddress));
  await confirm(game.connect(auditor).proveAuditDiligence(audit.taskId,
    selected.diligenceCheckpoint, selected.diligenceProof, selected.diligenceProofSiblingOnLeft));
  return confirm(game.connect(auditor).openChallenge(audit.taskId, audit.candidateTree.root,
    audit.index, audit.errorDigest, audit.transcript.leaves[0], audit.transcript.proof,
    audit.transcript.proofSiblingOnLeft));
}

// Builds only the not-yet-expanded branches of the authenticated disclosure
// frontier. Across an entire trace there are exactly N-1 three-tree splits.
export async function authenticatedBountyBatch({ availability, task, count }) {
  const start = Number(await availability.nextDisclosureIndex(task.taskId));
  const frontier = Array.from(await availability.getDisclosureFrontier(task.taskId), n => Number(n.size));
  if (start === 0 && frontier.length === 0) frontier.push(task.operatorTree.leafCount);
  const rows = task.plan.disclosureLeaves.slice(start, start + count), splits = [];
  const trees = [task.operatorTree, task.plan.programTree, task.plan.provenanceTree];
  for (let index = start; index < start + rows.length; index++) {
    if (!frontier.length) throw new Error('disclosure frontier exhausted');
    while (frontier.at(-1) > 1) {
      const size = frontier.pop();
      const branches = trees.map(tree => getSubtreeChildren(tree, index, index + size));
      splits.push({ left: branches.map(b => b.left), right: branches.map(b => b.right) });
      frontier.push(size / 2, size / 2);
    }
    frontier.pop();
  }
  return [task.taskId, rows.map(r => r.leaf), rows.map(r => r.lhsInputProof),
    rows.map(r => r.rhsInputProof), splits];
}

export async function relayBountyDisclosure({ availability, task, relayer, batchSize = 8 }) {
  batchSize = bountyRelayBatchSize(batchSize);
  while (Number(await availability.nextDisclosureIndex(task.taskId)) < task.plan.disclosureLeaves.length) {
    const args = await authenticatedBountyBatch({ availability, task, count: batchSize });
    await confirm(availability.connect(relayer).publishAuthenticatedTraceBatch(...args, { gasLimit: 20_000_000 }));
  }
}

export async function discloseAndBisectBountyChallenge({ game, availability,
  challenger, relayer = challenger, task, audit, batchSize = 8 }) {
  await relayBountyDisclosure({ availability, task, relayer, batchSize });
  let state = await game.getTaskDisputeState(task.taskId);
  while (Number(state.disputeEnd - state.disputeStart) > 1) {
    const range = [Number(state.disputeStart), Number(state.disputeEnd)];
    const op = getSubtreeChildren(task.operatorTree, ...range);
    const ch = getSubtreeChildren(audit.candidateTree, ...range);
    await confirm(game.connect(relayer).submitBisection(task.taskId, true, op.left, op.right));
    await confirm(game.connect(relayer).submitBisection(task.taskId, false, ch.left, ch.right));
    await confirm(game.connect(relayer).advanceDispute(task.taskId));
    state = await game.getTaskDisputeState(task.taskId);
  }
  return Number(state.disputeStart);
}

export function bountyLeafClaims(audit) {
  return [audit.taskId, traceLeafClaim(audit.operatorLeaves[audit.index]),
    traceLeafClaim(audit.candidateLeaves[audit.index])];
}

// This serializes certificates supplied by the existing independent public
// recomputation service. A client-supplied Boolean is never its own authority.
export async function settleBountyChallenge({ game, relayer, audit, resultHandle, signatures }) {
  const claims = bountyLeafClaims(audit);
  const binding = await game.leafDecisionBinding(audit.taskId, audit.index, claims[1].opcode);
  const proof = ethers.AbiCoder.defaultAbiCoder().encode(['bytes[]', 'bytes'], [[resultHandle, ...signatures], binding]);
  return confirm(game.connect(relayer).settleLeafViaAttestedDecision(...claims,
    claims[1].claimedHandle === resultHandle, claims[2].claimedHandle === resultHandle, proof,
    { gasLimit: 5_000_000 }));
}

// Runnable settlement demonstration using opaque fixture handles and local
// signers. It intentionally performs no FHE computation, uses no real data or
// KMS, and never connects to an existing chain. The production client helpers
// above accept the traces/certificates from the existing public-replay path.
export async function runCanonicalBountyDemo() {
  const { default: ganache } = await import('ganache');
  const backend = ganache.provider({ logging: { quiet: true }, wallet: { totalAccounts: 10 },
    chain: { chainId: 31337, time: new Date('2025-01-01T00:00:00Z') }, miner: { timestampIncrement: 0 } });
  const provider = new ethers.BrowserProvider(backend); provider.pollingInterval = 10;
  try {
    const signers = await Promise.all(Array.from({ length: 10 }, (_, i) => provider.getSigner(i)));
    const [requester, operator, ...others] = signers, auditors = others.slice(0, 3);
    const committee = Array.from({ length: 3 }, () => ethers.Wallet.createRandom());
    const profileDigest = ethers.id('opaque-bounty-demo-profile');
    const stack = await deployCanonicalBountyStack({ requester, committee: committee.map(s => s.address), profileDigest });
    const { game, verifier } = stack;
    await confirm(game.connect(operator).registerOperator({ value: ethers.parseEther('4') }));
    for (const auditor of auditors) await confirm(game.connect(auditor).registerAuditor({ value: ethers.parseEther('2') }));
    const domain = canonicalDomain(31337, verifier.target), contextDigest = ethers.id('opaque-demo-context');
    const past = async (taskId, phase) => {
      const deadline = Number((await game.getTaskDeadlines(taskId))[phase]);
      const raw = await provider.send('eth_getBlockByNumber', ['latest', false]);
      const now = Number(BigInt(raw.timestamp));
      if (now <= deadline) {
        await provider.send('evm_increaseTime', [deadline - now + 1]); await provider.send('evm_mine', []);
      }
    };
    const cases = [];
    for (const honest of [true, false]) {
      const taskId = ethers.id(`opaque-bounty-demo-${honest}`);
      const operatorLeaves = [{ opcode: 6, lhs: 1, rhs: 2, claimed: honest ? 3 : 4 }];
      const candidateLeaves = [{ ...operatorLeaves[0], claimed: 3 }];
      const task = await createBountyTask({ ...stack, requester, operator, taskId, operatorLeaves });
      const contextSignatures = await Promise.all(committee.slice(0, 2).map(w =>
        w.signTypedData(domain, CONTEXT_TYPES, { taskId, contextDigest })));
      await confirm(verifier.registerContext(taskId, contextDigest, contextSignatures));
      const assigned = await game.getAssignedAuditorsForLeaf(taskId, 0);
      const auditor = auditors.find(a => a.address.toLowerCase() === assigned[0].toLowerCase());
      const before = await game.getParticipantStake(auditor.address);
      const audit = await prepareSealedBountyAudit({ game, taskId, auditorAddress: auditor.address,
        operatorLeaves, candidateLeaves, index: 0, supportsOperator: honest });
      await commitSealedBountyAudit(game, auditor, audit); await past(taskId, 0);
      await revealSealedBountyAudit(game, requester, audit); await past(taskId, 1);
      if (honest) {
        await past(taskId, 2); await confirm(game.finalizeUnchallenged(taskId));
        await confirm(game.connect(auditor).claimAuditBond(taskId));
      } else {
        await proveAndOpenBountyChallenge(game, auditor, audit);
        await discloseAndBisectBountyChallenge({ ...stack, operator, challenger: auditor, task, audit });
        const resultHandle = traceLeafClaim(candidateLeaves[0]).claimedHandle;
        const binding = await game.leafDecisionBinding(taskId, 0, operatorLeaves[0].opcode);
        const signatures = await Promise.all(committee.slice(0, 2).map(w => w.signTypedData(domain, RESULT_TYPES,
          { profileDigest, contextDigest, leafBinding: ethers.keccak256(binding), resultHandle })));
        await settleBountyChallenge({ game, relayer: requester, audit, resultHandle, signatures });
      }
      const status = await game.getTaskStatus(taskId);
      cases.push({ kind: honest ? 'honest-acceptance' : 'correct-challenge', decision: Number(status.decision),
        auditorBalanceChangeWei: String((await game.getParticipantStake(auditor.address)) - before) });
    }
    if (cases[0].decision !== 1 || cases[0].auditorBalanceChangeWei !== '0' || cases[1].decision !== 2 ||
        BigInt(cases[1].auditorBalanceChangeWei) !== await game.CHALLENGE_BOUNTY_WEI())
      throw new Error('bounty demonstration settlement mismatch');
    return { classification: 'local-opaque-handle-demo-not-FHE-validation', status: 'passed',
      game: game.target, cases, totalBurnedWei: String(await game.totalBurnedWei()) };
  } finally { provider.destroy(); await backend.disconnect(); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv[2] !== '--demo') throw new Error('Usage: node scripts/canonical-bounty-client.mjs --demo');
  console.log(JSON.stringify(await runCanonicalBountyDemo(), null, 2));
}
