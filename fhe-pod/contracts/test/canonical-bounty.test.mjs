// Contract/accounting regressions only. The ciphertext handles and quorum
// certificates below are fixtures, not measured FHE or economic equilibria.
import nodeTest, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import solc from 'solc';
import { ethers, compileContracts, traceLeafClaim, selectAuditDiligenceCheckpoint } from '../../scripts/evm-lib.mjs';
import { canonicalDomain, CONTEXT_TYPES, RESULT_TYPES } from '../../scripts/canonical-chain.mjs';
import { BOUNTY_TEST_ECONOMICS } from '../../scripts/bounty-economics.mjs';
import { createProvider, signerFor, advanceTime, confirm, chainTimestamp } from './chain-harness.mjs';
import { deployCanonicalBountyStack, createBountyTask, prepareSealedBountyAudit,
  commitSealedBountyAudit, revealSealedBountyAudit, proveAndOpenBountyChallenge,
  discloseAndBisectBountyChallenge, authenticatedBountyBatch, relayBountyDisclosure,
  bountyLeafClaims, settleBountyChallenge, bountyRelayBatchSize } from '../../scripts/canonical-bounty-client.mjs';

const gas = { gasLimit: 5_000_000 }, ether = ethers.parseEther, coder = ethers.AbiCoder.defaultAbiCoder();
const evidence = { classification: 'local-EVM-bounty-regression-not-FHE-or-experiment-evaluation', tests: [], receipts: [] };
let sequence = 0, registeredTests = 0;
const test = (name, fn) => {
  registeredTests++;
  return nodeTest(name, async context => {
    try { await fn(context); evidence.tests.push({ name, status: 'passed' }); }
    catch (error) { evidence.tests.push({ name, status: 'failed', error: String(error.message) }); throw error; }
  });
};
async function sourceHashes() {
  const paths = ['../src/VerifiableFHEDisputeGame.sol', '../src/CanonicalBountyFHEDisputeGame.sol',
    '../src/CanonicalLeafVerifier.sol', '../src/AuthenticatedTraceAvailability.sol', '../src/BountyTraceAvailability.sol',
    '../../scripts/canonical-bounty-client.mjs', '../../scripts/bounty-economics.mjs',
    '../../scripts/bounty-economics.json', './canonical-bounty.test.mjs'];
  return Object.fromEntries(await Promise.all(paths.map(async file => [file,
    createHash('sha256').update(await fs.readFile(new URL(file, import.meta.url))).digest('hex')])));
}
const sourceHashesAtStart = await sourceHashes();
async function reject(action) {
  await assert.rejects(async () => { const r = await action(); if (r?.wait) await r.wait(); },
    e => e.code === 'CALL_EXCEPTION' || e.code === 'UNKNOWN_ERROR');
}
async function past(f, phase) {
  const deadline = Number((await f.game.getTaskDeadlines(f.task.taskId))[phase]);
  const now = await chainTimestamp(f.provider);
  if (now <= deadline) await advanceTime(f.provider, deadline - now + 1);
}
async function fixture({ operatorClaim = 4, candidateClaim = 3, leafCount = 1,
  operatorStake = ether('4'), penalty = ether('1'), bounty = ether('0.25'), overlap = false,
  maxTraceLeaves = 8, challengeCostBudgetWei = ether('0.1'), windowSeconds = 20 } = {}) {
  const provider = await createProvider({ totalAccounts: 14 }); provider.pollingInterval = 10;
  const signers = await Promise.all(Array.from({ length: 14 }, (_, i) => signerFor(provider, i)));
  const [requester, operator] = signers, auditors = overlap ? [operator, ...signers.slice(2, 4)] : signers.slice(2, 5),
    openers = signers.slice(5, 8), outsider = signers[8];
  const committee = Array.from({ length: 3 }, (_, i) => new ethers.Wallet(ethers.id(`bounty-signer-${i}`)));
  const profileDigest = ethers.id('bounty-fixture-profile');
  const stack = await deployCanonicalBountyStack({ requester, committee: committee.map(s => s.address),
    profileDigest, operatorPenaltyWei: penalty, bountyWei: bounty, maxTraceLeaves, challengeCostBudgetWei, windowSeconds });
  await confirm(stack.game.connect(operator).registerOperator({ value: operatorStake }));
  for (const a of auditors) await confirm(stack.game.connect(a).registerAuditor({ value: ether('2') }));
  const index = leafCount - 1;
  const leaves = Array.from({ length: leafCount }, (_, i) => ({ opcode: 6, lhs: 1, rhs: 2,
    claimed: i === index ? operatorClaim : 3, lhsRef: { kind: 'input', index: 0 }, rhsRef: { kind: 'input', index: 1 } }));
  const candidateLeaves = leaves.map((r, i) => ({ ...r, claimed: i === index ? candidateClaim : r.claimed }));
  const taskId = ethers.id(`bounty-task-${sequence++}`);
  const task = await createBountyTask({ ...stack, requester, operator, taskId, operatorLeaves: leaves });
  const chainId = Number((await provider.getNetwork()).chainId), domain = canonicalDomain(chainId, stack.verifier.target);
  const contextDigest = ethers.id(`context-${taskId}`);
  const contextSignatures = await Promise.all(committee.slice(0, 2).map(w =>
    w.signTypedData(domain, CONTEXT_TYPES, { taskId, contextDigest })));
  await confirm(stack.verifier.registerContext(taskId, contextDigest, contextSignatures));
  const assigned = await stack.game.getAssignedAuditorsForLeaf(taskId, index);
  const challenger = overlap ? operator : auditors.find(w => w.address.toLowerCase() === assigned[0].toLowerCase());
  const f = { ...stack, provider, signers, requester, operator, auditors, openers, outsider,
    committee, profileDigest, contextDigest, domain, task, leaves, candidateLeaves, index, challenger, penalty, bounty };
  f.audit = await makeAudit(f, challenger, candidateLeaves, operatorClaim === candidateClaim);
  return f;
}
async function makeAudit(f, auditor, candidateLeaves = f.candidateLeaves, supportsOperator = false) {
  return prepareSealedBountyAudit({ game: f.game, taskId: f.task.taskId, auditorAddress: auditor.address,
    operatorLeaves: f.leaves, candidateLeaves, index: f.index, supportsOperator });
}
async function commitAndReveal(f, entries = [[f.challenger, f.audit]]) {
  for (const [signer, audit] of entries) await commitSealedBountyAudit(f.game, signer, audit);
  await past(f, 0);
  for (const [, audit] of entries) await revealSealedBountyAudit(f.game, f.outsider, audit);
  await past(f, 1);
}
async function challenge(f, audit = f.audit, challenger = f.challenger, disclose = true) {
  await proveAndOpenBountyChallenge(f.game, challenger, audit);
  if (disclose) {
    const index = await discloseAndBisectBountyChallenge({ ...f, audit, challenger });
    assert.equal(index, audit.index);
  }
}
async function certificate(f, audit = f.audit, resultClaim = 3) {
  const resultHandle = traceLeafClaim({ ...audit.operatorLeaves[audit.index], claimed: resultClaim }).claimedHandle;
  const binding = await f.game.leafDecisionBinding(audit.taskId, audit.index, audit.operatorLeaves[audit.index].opcode);
  const body = { profileDigest: f.profileDigest, contextDigest: f.contextDigest,
    leafBinding: ethers.keccak256(binding), resultHandle };
  const signatures = await Promise.all(f.committee.slice(0, 2).map(w => w.signTypedData(f.domain, RESULT_TYPES, body)));
  return { resultHandle, signatures };
}
async function settle(f, audit = f.audit, resultClaim = 3) {
  const receipt = await settleBountyChallenge({ game: f.game, relayer: f.outsider,
    audit, ...await certificate(f, audit, resultClaim) });
  evidence.receipts.push({ label: 'settleCanonicalBounty', gasUsed: receipt.gasUsed.toString(), transactionHash: receipt.hash });
  return receipt;
}
async function stake(f, signer) { return f.game.getParticipantStake(signer.address); }
async function state(f) { return f.game.getTaskStatus(f.task.taskId); }
async function accounting(f, tasks = [f.task]) {
  const addresses = [...new Set(f.signers.map(s => s.address))];
  let sumStake = 0n, sumLocks = 0n, sumReservations = 0n;
  for (const address of addresses) {
    const b = await f.game.getParticipantStakeBreakdown(address);
    assert.ok(b.lockedChallengeBondWei <= b.totalStakeWei);
    sumStake += b.totalStakeWei; sumLocks += b.lockedChallengeBondWei;
    for (const task of tasks) sumReservations += await f.game.getAuditReservation(task.taskId, address);
  }
  for (const task of tasks) sumReservations += await f.game.getOperatorReservation(task.taskId);
  assert.equal(sumLocks, sumReservations, 'aggregate locks count each task/audit reservation exactly once');
  const balance = BigInt(await f.provider.send('eth_getBalance', [f.game.target, 'latest']));
  assert.equal(balance, sumStake + await f.game.totalBurnedWei(), 'no minting, loss, or spendable burned funds');
}

test('bounty version is constructor-fixed, deployable and cannot enable legacy reward/commit entry points', async () => {
  const f = await fixture();
  assert.equal(f.game.interface.getFunction('owner'), null);
  for (const name of ['CanonicalBountyFHEDisputeGame', 'CanonicalFHEDisputeGame', 'LegacyConfigurableDisputeGame']) {
    const a = f.artifacts[name]; assert.ok(a.deployedBytecodeBytes <= 24_576, name);
    assert.ok(ethers.getBytes(a.bytecode).length + 32 * 10 <= 49_152, name);
  }
  evidence.runtimeBytes = Object.fromEntries(Object.entries(f.artifacts)
    .filter(([name]) => /DisputeGame|Bounty/.test(name)).map(([name, a]) => [name, a.deployedBytecodeBytes]));
  await reject(() => f.game.connect(f.challenger).submitAudit(f.task.taskId, f.index, f.audit.transcript.root, f.audit.commitment, gas));
  await reject(() => f.game.connect(f.openers[0]).openVerdict(f.task.taskId, f.challenger.address, false,
    f.audit.salt, f.audit.transcript.root, gas));
});

test('deployment rejects publication/cost shortfalls, zero budgets and invalid trace bounds', async () => {
  const f = await fixture();
  const base = {requester:f.requester, committee:f.committee.map(s=>s.address),
    profileDigest:f.profileDigest, artifacts:f.artifacts};
  for (const change of [
    {maxTraceLeaves:128}, // The former 0.25 prize cannot pay the 0.276 fee.
    {bountyWei:ether('0.136')}, // Fee plus cost budget, without a positive margin.
    {operatorPenaltyWei:ether('0.286')}, // Reward plus fee, without an irreversible loss.
    {maxTraceLeaves:0}, {maxTraceLeaves:3}, {challengeCostBudgetWei:0n}
  ]) await reject(() => deployCanonicalBountyStack({...base,...change}));
});

test('trace-size admission cannot consume reserves outside the deployment cost bound', async () => {
  const f = await fixture({leafCount:8});
  assert.equal(await f.game.MAX_TRACE_LEAVES(),8n);
  const before = await f.game.getParticipantStakeBreakdown(f.operator.address);
  const taskId = ethers.id('over-budget-trace');
  await reject(() => createBountyTask({...f,taskId,operatorLeaves:[...f.leaves,...f.leaves]}));
  assert.equal(await f.game.getOperatorReservation(taskId),0n);
  assert.deepEqual(Array.from(await f.game.getParticipantStakeBreakdown(f.operator.address)),Array.from(before));
});

test('calibrated settlement covers disclosure plus declared costs and preserves the coalition loss floor', async () => {
  const c = BOUNTY_TEST_ECONOMICS;
  const f = await fixture({leafCount:8, maxTraceLeaves:c.maxTraceLeaves,
    penalty:BigInt(c.operatorPenaltyWei), bounty:BigInt(c.bountyWei),
    challengeCostBudgetWei:BigInt(c.challengeCostBudgetWei)});
  assert.equal(await f.game.MAX_DISCLOSURE_FEE_WEI(),BigInt(c.maxDisclosureFeeWei));
  const fee=await f.availability.requiredDisclosureBond(f.task.taskId);
  await confirm(f.availability.connect(f.challenger).requestTraceDisclosure(f.task.taskId,{value:fee}));
  await relayBountyDisclosure({...f,relayer:f.outsider});
  await commitAndReveal(f); await challenge(f); await settle(f); await accounting(f);
  assert.equal(await f.availability.claimableBond(f.operator.address),fee);
  assert.ok(f.bounty-fee-BigInt(c.challengeCostBudgetWei)>=BigInt(c.challengerMarginWei));
  assert.ok(f.penalty-f.bounty-fee>=BigInt(c.operatorLossFloorWei));
});

test('sealed commitment reveals neither index nor roots; early reveal and duplicate commit fail', async () => {
  const f = await fixture({ leafCount: 4 });
  const receipt = await commitSealedBountyAudit(f.game, f.challenger, f.audit);
  const tx = await f.provider.getTransaction(receipt.hash);
  assert.equal((tx.data.length - 2) / 2, 4 + 2 * 32);
  for (const secret of [f.audit.transcript.root, f.audit.candidateTree.root, f.audit.salt])
    assert.equal(tx.data.includes(secret.slice(2)), false);
  const status = await f.game.getAuditStatus(f.task.taskId, f.challenger.address);
  assert.equal(status.auditedLeafIndex, 0n); assert.equal(status.opened, false);
  for (const log of receipt.logs) {
    assert.equal(log.data.includes(f.audit.transcript.root.slice(2)), false);
    assert.equal(log.data.includes(f.audit.candidateTree.root.slice(2)), false);
  }
  await reject(() => revealSealedBountyAudit(f.game, f.outsider, f.audit));
  await reject(() => commitSealedBountyAudit(f.game, f.challenger, f.audit));
  await past(f, 0);
  await revealSealedBountyAudit(f.game, f.outsider, f.audit);
  assert.equal((await f.game.getAuditStatus(f.task.taskId, f.challenger.address)).auditedLeafIndex, 3n);
  await reject(() => revealSealedBountyAudit(f.game, f.outsider, f.audit));
});

test('identity copy, changed opening and late adaptation cannot acquire a valid audit', async () => {
  const f = await fixture(), copier = f.auditors.find(a => a.address !== f.challenger.address);
  await commitSealedBountyAudit(f.game, f.challenger, f.audit);
  await confirm(f.game.connect(copier).submitSealedAudit(f.task.taskId, f.audit.commitment));
  await past(f, 0);
  const forged = [...f.audit.opening]; forged[1] = copier.address;
  await reject(() => f.game.revealSealedAudit(...forged, gas));
  for (const [field, value] of [[2, 1], [3, ethers.id('wrong-root')], [4, ethers.id('wrong-candidate')],
    [5, true], [6, ethers.id('wrong-salt')]]) {
    const opening = [...f.audit.opening]; opening[field] = value;
    await reject(() => f.game.revealSealedAudit(...opening, gas));
  }
  await revealSealedBountyAudit(f.game, f.outsider, f.audit);
  const late = f.auditors.find(a => a.address !== copier.address && a.address !== f.challenger.address);
  const lateAudit = await makeAudit(f, late);
  await reject(() => commitSealedBountyAudit(f.game, late, lateAudit));
});

test('honest unchallenged task accepts without paying for agreement or a checkpoint', async () => {
  const f = await fixture({ operatorClaim: 3 }), audit = await makeAudit(f, f.challenger, f.leaves, true);
  const before = await stake(f, f.challenger);
  await commitAndReveal(f, [[f.challenger, audit]]);
  await confirm(f.game.sealDiligenceRandomness(f.task.taskId));
  await past(f, 2); await confirm(f.game.finalizeUnchallenged(f.task.taskId));
  assert.equal((await state(f)).decision, 1n);
  await confirm(f.game.connect(f.challenger).claimAuditBond(f.task.taskId));
  assert.equal(await stake(f, f.challenger), before);
  await reject(() => f.game.connect(f.challenger).claimAuditBond(f.task.taskId, gas));
  const cp = selectAuditDiligenceCheckpoint(audit.transcript,
    await f.game.getRequiredDiligenceCheckpointIndex(f.task.taskId, f.challenger.address));
  await reject(() => f.game.connect(f.challenger).claimDiligenceReward(f.task.taskId,
    cp.diligenceCheckpoint, cp.diligenceProof, cp.diligenceProofSiblingOnLeft, gas));
});

test('correct committed challenger wins one funded bounty through authenticated bisection; relayer earns nothing', async () => {
  const f = await fixture({ leafCount: 4 });
  const before = await Promise.all([f.operator, f.challenger, f.outsider].map(s => stake(f, s)));
  await commitAndReveal(f); await challenge(f); await settle(f);
  await accounting(f);
  assert.equal((await state(f)).decision, 2n);
  assert.equal(await stake(f, f.operator), before[0] - f.penalty);
  assert.equal(await stake(f, f.challenger), before[1] + f.bounty);
  assert.equal(await stake(f, f.outsider), before[2]);
  await reject(() => settle(f));
  assert.equal(await stake(f, f.challenger), before[1] + f.bounty);
  assert.ok((await stake(f, f.operator)) + (await stake(f, f.challenger)) < before[0] + before[1],
    'operator-challenger coalition must lose funds even when challenge wins');
});

test('both invalid results reject the operator but do not pay a fabricated challenger', async () => {
  const f = await fixture({ candidateClaim: 5 });
  const before = await Promise.all([f.operator, f.challenger].map(s => stake(f, s)));
  await commitAndReveal(f); await challenge(f); const receipt = await settle(f);
  const resolved = receipt.logs.map(log => { try { return f.game.interface.parseLog(log); } catch { return null; } })
    .find(log => log?.name === 'TaskResolved');
  assert.equal(resolved.args.winner, ethers.ZeroAddress);
  assert.equal((await state(f)).decision, 2n);
  assert.equal(await stake(f, f.operator), before[0] - f.penalty);
  assert.ok(await stake(f, f.challenger) < before[1]);
  await reject(() => f.game.finalizeUnchallenged(f.task.taskId, gas));
});

test('false challenge loses its reserved bond once and reopens an honest task', async () => {
  const f = await fixture({ operatorClaim: 3, candidateClaim: 4 });
  const before = await stake(f, f.challenger), operatorBefore = await stake(f, f.operator);
  await commitAndReveal(f); await challenge(f); await settle(f);
  assert.equal((await state(f)).status, 1n);
  const afterLoss = await stake(f, f.challenger); assert.ok(afterLoss < before);
  assert.ok((await stake(f, f.operator)) + afterLoss < operatorBefore + before,
    'correct operator and false challenger cannot recover the entire failed-challenge penalty');
  await reject(() => proveAndOpenBountyChallenge(f.game, f.challenger, f.audit));
  await past(f, 2); await confirm(f.game.finalizeUnchallenged(f.task.taskId));
  assert.equal((await state(f)).decision, 1n);
  assert.equal(await stake(f, f.challenger), afterLoss);
});

test('unadmitted garbage cannot freeze a task; admitted adjudicator outage preserves balances and later recovers', async () => {
  const f = await fixture(); await commitAndReveal(f); await challenge(f);
  const claims = bountyLeafClaims(f.audit);
  await reject(() => f.game.settleLeafViaAttestedDecision(claims[0], claims[1],
    { ...claims[2], claimedHandle: ethers.id('uncommitted') }, false, false, '0x', gas));
  assert.equal((await f.game.getPendingFhevmLeafResolution(f.task.taskId)).active, false);
  await confirm(f.game.settleLeafViaAttestedDecision(...claims, false, false, '0x', gas));
  const before = await Promise.all([f.operator, f.challenger].map(s => stake(f, s)));
  await advanceTime(f.provider, 100);
  await reject(() => f.game.timeoutDispute(f.task.taskId, gas));
  await reject(() => f.game.finalizeUnchallenged(f.task.taskId, gas));
  assert.deepEqual(await Promise.all([f.operator, f.challenger].map(s => stake(f, s))), before);
  const c = await certificate(f);
  for (const signatures of [[c.signatures[0]], [c.signatures[0], c.signatures[0]]])
    await reject(() => settleBountyChallenge({ game: f.game, relayer: f.outsider, audit: f.audit, ...c, signatures }));
  await settle(f); assert.equal((await state(f)).decision, 2n);
});

test('commitment is bound to chain, game, task and identity, including copied commits made before opening', async () => {
  const f = await fixture();
  const typehash = ethers.id('FHE_BOUNTY_AUDIT_V2(uint256 chainId,address game,bytes32 taskId,address auditor,uint32 leafIndex,bytes32 podRoot,bytes32 candidateTraceRoot,bool supportsOperator,bytes32 salt)');
  const chainId = (await f.provider.getNetwork()).chainId;
  const hash = (audit, changes = {}) => ethers.keccak256(coder.encode(
    ['bytes32', 'uint256', 'address', 'bytes32', 'address', 'uint32', 'bytes32', 'bytes32', 'bool', 'bytes32'],
    [typehash, changes.chainId ?? chainId, changes.game ?? f.game.target,
      changes.taskId ?? audit.taskId, changes.auditor ?? audit.auditorAddress, audit.index,
      audit.transcript.root, audit.candidateTree.root, audit.supportsOperator, audit.salt]));
  assert.equal(hash(f.audit), f.audit.commitment);
  const malformed = [];
  for (const [i, change] of [{ chainId: chainId + 1n }, { game: f.outsider.address }, { taskId: ethers.id('another-task') }].entries()) {
    const auditor = f.auditors[i], audit = await makeAudit(f, auditor);
    await confirm(f.game.connect(auditor).submitSealedAudit(f.task.taskId, hash(audit, change)));
    malformed.push(audit);
  }
  await past(f, 0);
  for (const audit of malformed) await reject(() => revealSealedBountyAudit(f.game, f.outsider, audit));
});

test('an authenticated malformed sham loses once and cannot suppress the prior honest challenger', async () => {
  const f = await fixture(), sham = f.auditors.find(a => a.address !== f.challenger.address);
  const shamLeaves = f.candidateLeaves.map(r => ({ ...r, lhs: 9 }));
  const shamAudit = await makeAudit(f, sham, shamLeaves);
  await commitAndReveal(f, [[sham, shamAudit], [f.challenger, f.audit]]);
  await challenge(f, shamAudit, sham);
  const before = await stake(f, sham);
  await confirm(f.game.settleLeafViaAttestedDecision(...bountyLeafClaims(shamAudit), false, false, '0x', gas));
  assert.equal((await state(f)).status, 1n); assert.ok(await stake(f, sham) < before);
  const afterLoss = await stake(f, sham);
  await reject(() => proveAndOpenBountyChallenge(f.game, sham, shamAudit));
  await challenge(f); await settle(f);
  assert.equal((await state(f)).decision, 2n);
  assert.equal(await stake(f, sham), afterLoss);
});

test('secondary correct reporters recover only their own bond and never share the challenger bounty', async () => {
  const f = await fixture(), secondary = f.auditors.find(a => a.address !== f.challenger.address);
  const secondaryAudit = await makeAudit(f, secondary);
  const before = await stake(f, secondary);
  await commitAndReveal(f, [[f.challenger, f.audit], [secondary, secondaryAudit]]);
  await challenge(f); await settle(f);
  await confirm(f.game.connect(secondary).claimAuditBond(f.task.taskId));
  assert.equal(await stake(f, secondary), before);
  const cp = selectAuditDiligenceCheckpoint(secondaryAudit.transcript,
    await f.game.getRequiredDiligenceCheckpointIndex(f.task.taskId, secondary.address));
  await reject(() => f.game.connect(secondary).claimDiligenceReward(f.task.taskId,
    cp.diligenceCheckpoint, cp.diligenceProof, cp.diligenceProofSiblingOnLeft, gas));
});

test('unrewarded same-leaf opinions cannot fund the challenger or the operator-challenger coalition', async () => {
  const f = await fixture(), supporter = f.auditors.find(a => a.address !== f.challenger.address);
  const support = await makeAudit(f, supporter, f.leaves, true);
  const before = await Promise.all([f.operator, f.challenger, supporter].map(s => stake(f, s)));
  await commitAndReveal(f, [[f.challenger, f.audit], [supporter, support]]);
  await challenge(f); await settle(f);
  assert.equal(await stake(f, f.challenger), before[1] + f.bounty);
  assert.equal(await stake(f, supporter), before[2]);
  assert.ok((await stake(f, f.operator)) + (await stake(f, f.challenger)) < before[0] + before[1]);
  await confirm(f.game.connect(supporter).claimAuditBond(f.task.taskId));
  assert.equal(await stake(f, supporter), before[2]);
});

test('operator stake is reserved separately for concurrent tasks and cannot be reused or withdrawn', async () => {
  const f = await fixture();
  assert.equal(await f.game.getOperatorReservation(f.task.taskId), f.penalty);
  const tasks = [f.task];
  for (let i = 0; i < 3; i++) tasks.push(await createBountyTask({ ...f,
    taskId: ethers.id(`reserved-${sequence++}`), operatorLeaves: f.leaves }));
  const breakdown = await f.game.getParticipantStakeBreakdown(f.operator.address);
  assert.equal(breakdown.availableStakeWei, 0n);
  await reject(() => f.game.connect(f.operator).withdraw(1n, f.operator.address, gas));
  await reject(() => createBountyTask({ ...f, taskId: ethers.id(`unfunded-${sequence++}`), operatorLeaves: f.leaves }));
  await past(f, 2); await confirm(f.game.finalizeUnchallenged(f.task.taskId));
  assert.equal(await f.game.getOperatorReservation(f.task.taskId), 0n);
  await confirm(f.game.connect(f.operator).withdraw(f.penalty, f.outsider.address));
  assert.equal(await stake(f, f.operator), ether('3'));
  for (const task of tasks.slice(1)) assert.equal(await f.game.getOperatorReservation(task.taskId), f.penalty);
});

test('voluntary unopened commitment loses only its reserved bond; a nonparticipant is never fined', async () => {
  const f = await fixture(), idle = f.auditors.find(a => a.address !== f.challenger.address);
  const before = await Promise.all([f.challenger, idle, f.outsider].map(s => stake(f, s)));
  await commitSealedBountyAudit(f.game, f.challenger, f.audit);
  const reserve = await f.game.getAuditReservation(f.task.taskId, f.challenger.address);
  assert.ok(reserve > 0n);
  await reject(() => f.game.slashLazyAuditor(f.task.taskId, f.challenger.address, gas));
  await past(f, 1);
  await confirm(f.game.connect(f.outsider).slashLazyAuditor(f.task.taskId, f.challenger.address));
  assert.equal(await stake(f, f.challenger), before[0] - reserve);
  assert.equal(await stake(f, idle), before[1]); assert.equal(await stake(f, f.outsider), before[2]);
  await reject(() => f.game.slashLazyAuditor(f.task.taskId, idle.address, gas));
  await reject(() => f.game.slashLazyAuditor(f.task.taskId, f.challenger.address, gas));
});

test('prechallenge withholding rejects operator, pays no computation bounty and refunds a commitment closed before reveal', async () => {
  const f = await fixture();
  await commitSealedBountyAudit(f.game, f.challenger, f.audit);
  const before = await Promise.all([f.operator, f.challenger].map(s => stake(f, s)));
  const bond = await f.availability.requiredDisclosureBond(f.task.taskId);
  await confirm(f.availability.connect(f.challenger).requestTraceDisclosure(f.task.taskId, { value: bond }));
  await advanceTime(f.provider, 21);
  await confirm(f.availability.connect(f.outsider).markDisputeTraceUnavailable(f.task.taskId));
  assert.equal((await state(f)).decision, 2n);
  assert.equal(await stake(f, f.operator), before[0] - f.penalty);
  await confirm(f.game.connect(f.challenger).claimAuditBond(f.task.taskId));
  assert.equal(await stake(f, f.challenger), before[1]);
  assert.equal(await f.availability.claimableBond(f.challenger.address), bond);
  await reject(() => f.game.finalizeUnchallenged(f.task.taskId, gas));
});

test('public disclosure extends commit phase without permitting commitments after a revealed opening', async () => {
  const f = await fixture();
  const oldDeadline = (await f.game.getTaskDeadlines(f.task.taskId))[0];
  await confirm(f.availability.connect(f.challenger).requestTraceDisclosure(f.task.taskId,
    { value: await f.availability.requiredDisclosureBond(f.task.taskId) }));
  assert.ok((await f.game.getTaskDeadlines(f.task.taskId))[0] > oldDeadline);
  await relayBountyDisclosure({ ...f, relayer: f.operator });
  await commitSealedBountyAudit(f.game, f.challenger, f.audit); await past(f, 0);
  await revealSealedBountyAudit(f.game, f.outsider, f.audit);
  const late = f.auditors.find(a => a.address !== f.challenger.address);
  const lateAudit = await makeAudit(f, late);
  await reject(() => commitSealedBountyAudit(f.game, late, lateAudit));
  await reject(() => f.availability.connect(late).requestTraceDisclosure(f.task.taskId,
    { value: 1n, ...gas }));
});

test('full replay cohort is eligible at every leaf and a previously excluded leaf can be challenged', async () => {
  const f = await fixture({ leafCount: 8 });
  const cohort = Array.from(await f.game.getAssignedAuditors(f.task.taskId)).map(a => a.toLowerCase()).sort();
  for (let index = 0; index < 8; index++) {
    const assigned = Array.from(await f.game.getAssignedAuditorsForLeaf(f.task.taskId, index)).map(a => a.toLowerCase()).sort();
    assert.deepEqual(assigned, cohort);
    for (const auditor of f.auditors)
      assert.equal(await f.game.isAuditorAssignedToLeaf(f.task.taskId, auditor.address, index), true);
  }
  await commitAndReveal(f); await challenge(f); await settle(f);
  assert.equal((await state(f)).decision, 2n);
});

test('withdrawals transfer spendable funds once, preserve role floors, and resist callback reentry or rejection', async () => {
  const f = await fixture();
  const source = `pragma solidity ^0.8.24;
    interface Game { function registerAuditor() external payable; function withdraw(uint256,address payable) external; }
    contract WithdrawalReceiver {
      Game public game; uint public attempts; bool public reentered;
      function run(address target) external payable {
        game = Game(target); game.registerAuditor{value: msg.value}(); game.withdraw(1 ether, payable(address(this)));
      }
      receive() external payable { attempts++; if(attempts == 1) (reentered,) = address(game).call(
        abi.encodeWithSelector(Game.withdraw.selector, 1 ether, address(this))); }
    }
    contract RejectReceiver { receive() external payable { revert(); } }`;
  const build = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity', sources: { 'Receiver.sol': { content: source } },
    settings: { evmVersion: 'paris', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })));
  assert.equal((build.errors ?? []).filter(e => e.severity === 'error').length, 0);
  const deploy = async name => {
    const a = build.contracts['Receiver.sol'][name];
    const c = await new ethers.ContractFactory(a.abi, a.evm.bytecode.object, f.requester).deploy();
    await c.waitForDeployment(); return c;
  };
  const receiver = await deploy('WithdrawalReceiver'), rejector = await deploy('RejectReceiver');
  await confirm(receiver.run(f.game.target, { value: ether('2'), ...gas }));
  assert.equal(await receiver.attempts(), 1n); assert.equal(await receiver.reentered(), false);
  assert.equal(await f.game.getParticipantStake(receiver.target), ether('1'));
  assert.equal(BigInt(await f.provider.send('eth_getBalance', [receiver.target, 'latest'])), ether('1'));
  const before = await stake(f, f.challenger);
  await reject(() => f.game.connect(f.challenger).withdraw(ether('1'), rejector.target, gas));
  assert.equal(await stake(f, f.challenger), before);
  await confirm(f.game.connect(f.challenger).withdraw(ether('1'), f.outsider.address));
  assert.equal(await stake(f, f.challenger), ether('1'));
  await reject(() => f.game.connect(f.challenger).withdraw(1n, f.outsider.address, gas));
});

test('same address as operator and challenger preserves aggregate reservations and loses funds on every dispute outcome', async () => {
  for (const [operatorClaim, candidateClaim] of [[4, 3], [4, 5], [3, 4]]) {
    const f = await fixture({ overlap: true, operatorClaim, candidateClaim });
    const before = await stake(f, f.operator);
    await commitAndReveal(f);
    const bond = await f.game.getAuditReservation(f.task.taskId, f.operator.address);
    assert.equal((await f.game.getParticipantStakeBreakdown(f.operator.address)).lockedChallengeBondWei, f.penalty + bond);
    await accounting(f); await challenge(f); await accounting(f); await settle(f); await accounting(f);
    const expectedLoss = operatorClaim === 3 ? bond - bond / 2n :
      candidateClaim === 3 ? f.penalty - f.bounty : f.penalty + bond;
    assert.equal(await stake(f, f.operator), before - expectedLoss);
    if (operatorClaim === 3) { await past(f, 2); await confirm(f.game.finalizeUnchallenged(f.task.taskId)); }
    assert.equal((await f.game.getParticipantStakeBreakdown(f.operator.address)).lockedChallengeBondWei, 0n);
    await accounting(f);
  }
});

test('audit reservations cannot finance several simultaneous commitments or be locked twice on challenge', async () => {
  const f = await fixture({ operatorClaim: 3 });
  const tasks = [f.task], audits = [await makeAudit(f, f.challenger, f.leaves, true)];
  for (let i = 0; i < 3; i++) {
    const task = await createBountyTask({ ...f, taskId: ethers.id(`audit-reserve-${sequence++}`), operatorLeaves: f.leaves });
    tasks.push(task);
    audits.push(await prepareSealedBountyAudit({ game: f.game, taskId: task.taskId,
      auditorAddress: f.challenger.address, operatorLeaves: f.leaves, candidateLeaves: f.leaves, index: 0, supportsOperator: true }));
  }
  for (const audit of audits) await commitSealedBountyAudit(f.game, f.challenger, audit);
  assert.equal((await f.game.getParticipantStakeBreakdown(f.challenger.address)).availableStakeWei, 0n);
  await reject(() => f.game.connect(f.challenger).withdraw(1n, f.challenger.address, gas));
  await accounting(f, tasks);
  await past(f, 0);
  for (const audit of audits) await revealSealedBountyAudit(f.game, f.outsider, audit);
  await past(f, 2);
  for (const task of tasks) {
    await confirm(f.game.finalizeUnchallenged(task.taskId));
    await confirm(f.game.connect(f.challenger).claimAuditBond(task.taskId));
  }
  assert.equal((await f.game.getParticipantStakeBreakdown(f.challenger.address)).lockedChallengeBondWei, 0n);
  await accounting(f, tasks);
});

test('an unrelayed stalled bisection has no computational bounty; silence alone is not a computation proof', async () => {
  for (const missingOperator of [true, false]) {
    const f = await fixture({ leafCount: 4 }); await commitAndReveal(f);
    await challenge(f, f.audit, f.challenger, false);
    await relayBountyDisclosure({ ...f, relayer: f.operator });
    const tree = missingOperator ? f.audit.candidateTree : f.task.operatorTree;
    const branch = tree.levels[tree.levels.length - 2];
    await confirm(f.game.connect(missingOperator ? f.challenger : f.operator)
      .submitBisection(f.task.taskId, !missingOperator, branch[0], branch[1]));
    const before = await Promise.all([f.operator, f.challenger].map(s => stake(f, s)));
    await advanceTime(f.provider, 61); await confirm(f.game.timeoutDispute(f.task.taskId, gas));
    assert.equal((await state(f)).decision, missingOperator ? 2n : 0n);
    assert.equal(await stake(f, f.challenger), missingOperator ? before[1] : before[1] - ether('0.5'));
    if (missingOperator) assert.equal(await stake(f, f.operator), before[0] - f.penalty);
    await accounting(f);
  }
});

test('operator disappears after task creation: a relay completes disclosure, both branches and payment to the correct challenger', async () => {
  for (const leafCount of [1, 8]) {
    const f = await fixture({ leafCount }); await commitAndReveal(f);
    await challenge(f, f.audit, f.challenger, false);
    await reject(() => f.game.connect(f.operator).timeoutDispute(f.task.taskId, gas));
    const balance = await stake(f, f.challenger), relayBalance = await stake(f, f.outsider);
    await discloseAndBisectBountyChallenge({ ...f, relayer: f.outsider, batchSize: 3 });
    await settle(f);
    assert.equal((await state(f)).decision, 2n);
    assert.equal(await stake(f, f.challenger), balance + f.bounty);
    assert.equal(await stake(f, f.outsider), relayBalance, 'relay cannot steal the prize');
    await confirm(f.game.connect(f.challenger).withdraw(f.bounty, f.outsider.address));
    await reject(() => settle(f));
    await accounting(f);
  }
});

test('permissionless disclosure authenticates every partial prefix; invalid data cannot poison the frontier', async () => {
  const f = await fixture({ leafCount: 8 }); await commitAndReveal(f);
  await challenge(f, f.audit, f.challenger, false);
  const args = await authenticatedBountyBatch({ ...f, count: 1 });
  for (const field of ['claimedHandle', 'lhsSourceIndex', 'lhsInputRecord']) {
    const bad = structuredClone(args);
    bad[1][0][field] = field === 'lhsSourceIndex' ? 1 : ethers.id(`bad-${field}`);
    await reject(() => f.availability.connect(f.outsider).publishAuthenticatedTraceBatch(...bad, gas));
    assert.equal(await f.availability.nextDisclosureIndex(f.task.taskId), 0n);
    assert.equal((await f.availability.getDisclosureFrontier(f.task.taskId)).length, 0);
  }
  for (let tree = 0; tree < 3; tree++) {
    const bad = structuredClone(args); bad[4][0].right[tree] = ethers.id(`bad-tree-${tree}`);
    await reject(() => f.availability.connect(f.operator).publishAuthenticatedTraceBatch(...bad, gas));
  }
  await reject(() => f.availability.connect(f.operator).publishDisputedTraceBatch(...args.slice(0, 4), gas));
  await confirm(f.availability.connect(f.operator).publishAuthenticatedTraceBatch(...args, gas));
  assert.equal(await f.availability.nextDisclosureIndex(f.task.taskId), 1n);
  await reject(() => f.availability.connect(f.outsider).publishAuthenticatedTraceBatch(...args, gas));
  await relayBountyDisclosure({ ...f, relayer: f.outsider, batchSize: 3 });
  assert.equal(await f.availability.isDisputeReady(f.task.taskId), true);
  assert.equal((await f.availability.getDisclosureFrontier(f.task.taskId)).length, 0);
});

test('disclosure authentication uses exactly N-1 splits for arbitrary batch boundaries', async () => {
  for (const batchSize of [1, 3, 8]) {
    const f = await fixture({ leafCount: 8 }); await commitAndReveal(f);
    await challenge(f, f.audit, f.challenger, false);
    let splits = 0;
    while (!await f.availability.isDisputeReady(f.task.taskId)) {
      const args = await authenticatedBountyBatch({ ...f, count: batchSize });
      splits += args[4].length;
      await confirm(f.availability.connect(f.outsider).publishAuthenticatedTraceBatch(...args, gas));
    }
    assert.equal(splits, 7);
  }
});

test('late forced disclosure reserves a complete replay window after its latest publication', async () => {
  const f = await fixture();
  const oldCommit = Number((await f.game.getTaskDeadlines(f.task.taskId))[0]);
  const now = await chainTimestamp(f.provider);
  await advanceTime(f.provider, oldCommit - now);
  const fee = await f.availability.requiredDisclosureBond(f.task.taskId);
  await confirm(f.availability.connect(f.challenger).requestTraceDisclosure(f.task.taskId, { value: fee }));
  const disclosureEnd = Number(await f.availability.disclosureDeadline(f.task.taskId));
  const newCommit = Number((await f.game.getTaskDeadlines(f.task.taskId))[0]);
  assert.equal(newCommit - disclosureEnd, 20);
  await advanceTime(f.provider, disclosureEnd - await chainTimestamp(f.provider));
  await relayBountyDisclosure({ ...f, relayer: f.outsider });
  await commitSealedBountyAudit(f.game, f.challenger, f.audit);
  await reject(() => revealSealedBountyAudit(f.game, f.outsider, f.audit));
  await past(f, 0); await revealSealedBountyAudit(f.game, f.outsider, f.audit); await past(f, 1);
  await challenge(f); await settle(f);
  // The separate disclosure fee is credited on publication, even if a later
  // computation certificate rejects the operator. It is an auditor cost.
  assert.equal(await f.availability.claimableBond(f.operator.address), fee);
  assert.equal(await f.availability.claimableBond(f.challenger.address), 0n);
  await accounting(f);
});

test('512-leaf disclosure splits a requested 64-row batch within the relay gas budget', async () => {
  assert.equal(bountyRelayBatchSize(64), 48);
  assert.equal(bountyRelayBatchSize(8), 8);
  for (const value of [0, 65, 1.5]) assert.throws(() => bountyRelayBatchSize(value));
  const f = await fixture({leafCount:512, maxTraceLeaves:512, windowSeconds:120,
    operatorStake:ether('6'), penalty:BigInt(BOUNTY_TEST_ECONOMICS.operatorPenaltyWei),
    bounty:BigInt(BOUNTY_TEST_ECONOMICS.bountyWei),
    challengeCostBudgetWei:BigInt(BOUNTY_TEST_ECONOMICS.challengeCostBudgetWei)});
  const bond = await f.availability.requiredDisclosureBond(f.task.taskId);
  await confirm(f.availability.connect(f.challenger).requestTraceDisclosure(f.task.taskId,{value:bond}));
  const before = Number(BigInt(await f.provider.send('eth_blockNumber',[])));
  await relayBountyDisclosure({...f,task:f.task,relayer:f.outsider,batchSize:64});
  assert.equal(await f.availability.nextDisclosureIndex(f.task.taskId),512n);
  assert.equal(await f.availability.isCleared(f.task.taskId),true);
  const afterBlock = Number(BigInt(await f.provider.send('eth_blockNumber',[])));
  let batches = 0, maximumGas = 0n;
  for (let block=before+1;block<=afterBlock;block++) {
    const data=await f.provider.getBlock(block,true);
    for(const tx of data.prefetchedTransactions) {
      if(tx.to?.toLowerCase()!==f.availability.target.toLowerCase()) continue;
      const receipt=await f.provider.getTransactionReceipt(tx.hash);
      assert.equal(receipt.status,1);assert.ok(receipt.gasUsed<20_000_000n);batches++;
      if(receipt.gasUsed>maximumGas)maximumGas=receipt.gasUsed;
    }
  }
  assert.equal(batches,11);
  evidence.tests.push({name:'512-leaf-disclosure-gas-and-window',leaves:512,batches,
    windowSeconds:120,maximumGas:String(maximumGas),gasLimit:'20000000'});
});

after(async () => {
  const output = process.env.VCFHE_BOUNTY_EVIDENCE;
  if (!output) return;
  evidence.sourceHashes = await sourceHashes();
  evidence.sourceHashesAtStart = sourceHashesAtStart;
  evidence.sourceUnchanged = JSON.stringify(evidence.sourceHashes) === JSON.stringify(sourceHashesAtStart);
  evidence.testCount = registeredTests;
  evidence.passedCount = evidence.tests.filter(t => t.status === 'passed').length;
  evidence.status = evidence.sourceUnchanged && evidence.tests.length === registeredTests &&
    evidence.passedCount === registeredTests ? 'passed' : 'failed';
  await fs.writeFile(output, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
});
