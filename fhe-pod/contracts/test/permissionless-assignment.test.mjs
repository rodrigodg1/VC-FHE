import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { ethers, compileContracts, buildMerkleTree, boundCreateTaskArgs,
  terminalOutputBinding, authorizeAuthenticatedTask, traceLeafClaim, leafHash,
  buildAuditTranscript, challengeErrorDigest, selectAuditDiligenceCheckpoint } from "../../scripts/evm-lib.mjs";
import { createCanonicalGame } from "../../scripts/canonical-game-driver.mjs";
import { canonicalDomain, CONTEXT_TYPES, RESULT_TYPES } from "../../scripts/canonical-chain.mjs";
import { createProvider, signerFor, advanceBlocks, advanceTime, confirm } from "./chain-harness.mjs";

const evidence = { classification: "local-EVM-regression-not-experiment-evaluation", receipts: [] };
const leaves = [{ opcode: 6, lhs: 1, rhs: 2, claimed: 3 }];
const tree = buildMerkleTree(leaves);
const stake = { value: ethers.parseEther("1") };
const gas = { gasLimit: 5_000_000 };
const coder = ethers.AbiCoder.defaultAbiCoder();
const record = async (label, promise) => {
  const receipt = await confirm(promise);
  evidence.receipts.push({ label, gasUsed: receipt.gasUsed.toString(), transactionHash: receipt.hash,
    blockNumber: receipt.blockNumber, status: receipt.status });
  return receipt;
};
async function reject(action) {
  await assert.rejects(async () => {
    const result = await action();
    if (result?.wait) await result.wait();
  }, error => error.code === "CALL_EXCEPTION" || error.code === "UNKNOWN_ERROR");
}

async function fixture({ threshold = 2, wrongBinding = false } = {}) {
  const provider = await createProvider({ totalAccounts: 18 });
  const signers = await Promise.all(Array.from({ length: 18 }, (_, i) => signerFor(provider, i)));
  const [requester, operator] = signers;
  const artifacts = await compileContracts();
  const deploy = async (name, args = []) => {
    const c = await new ethers.ContractFactory(artifacts[name].abi, artifacts[name].bytecode, requester).deploy(...args);
    await record(`deploy:${name}`, c.deploymentTransaction()); return c;
  };
  const objective = await deploy("ObjectiveMicroVerifier");
  const nonce = BigInt(await provider.send("eth_getTransactionCount", [requester.address, "pending"]));
  const gameAddress = ethers.getCreateAddress({ from: requester.address, nonce: nonce + 2n });
  const moduleGame = wrongBinding ? operator.address : gameAddress;
  const availability = await deploy("AuthenticatedTraceAvailability", [moduleGame, 20]);
  const committee = Array.from({ length: 3 }, (_, i) => new ethers.Wallet(ethers.id(`assignment-test-signer-${i}`)));
  const verifier = await deploy("CanonicalLeafVerifier", [moduleGame, ethers.id("profile"), committee.map(s => s.address), threshold]);
  const args = [objective.target, 20, 20, 20, availability.target, verifier.target];
  if (wrongBinding || threshold === 1) {
    await reject(() => deploy("CanonicalFHEDisputeGame", args)); return;
  }
  const game = await deploy("CanonicalFHEDisputeGame", args);
  assert.equal(game.target, gameAddress);
  const auditors = signers.slice(2, 6), openers = signers.slice(6, 10);
  await confirm(game.connect(operator).registerOperator({ value: ethers.parseEther("2") }));
  for (const auditor of auditors) await confirm(game.connect(auditor).registerAuditor(stake));
  for (const opener of openers) await confirm(game.connect(opener).registerDecryptor(stake));
  const create = async label => {
    const taskId = ethers.id(label), outputAttestationHash = ethers.id(`output-${label}`);
    const binding = terminalOutputBinding(taskId, tree, leaves, outputAttestationHash);
    const plan = await authorizeAuthenticatedTask({ availability, requester, operatorAddress: operator.address,
      taskId, tree, leaves, resultHash: binding.resultHash, outputAttestationHash });
    const receipt = await record("createTask", game.connect(operator).createTask(
      ...boundCreateTaskArgs(taskId, tree, leaves, outputAttestationHash)));
    return { taskId, receipt, plan };
  };
  return { provider, game, availability, verifier, objective, committee, artifacts,
    requester, operator, auditors, openers, late: signers.slice(10, 14), outsider: signers[14], create };
}

function expected(pool, taskId, seed, role) {
  const domain = ethers.keccak256(coder.encode(["bytes32", "bytes32", "string"], [taskId, seed, role]));
  const max = (1n << 256n) - 1n, size = BigInt(pool.length), cutoff = max - max % size;
  const indices = [];
  for (let i = 0; i < 3; i++) for (let attempt = 0; ; attempt++) {
    const draw = BigInt(ethers.keccak256(coder.encode(["bytes32", "uint256", "uint256"], [domain, i, attempt])));
    if (draw >= cutoff) continue;
    const index = Number(draw % size);
    if (indices.includes(index)) continue;
    indices.push(index); break;
  }
  return indices.map(i => pool[i].address);
}

async function checkCohorts(f, taskId, seed, auditors = f.auditors, openers = f.openers) {
  assert.deepEqual(Array.from(await f.game.getAssignedAuditors(taskId)), expected(auditors, taskId, seed, "auditors"));
  assert.deepEqual(Array.from(await f.game.getAssignedDecryptors(taskId)), expected(openers, taskId, seed, "decryptors"));
}

test("canonical deployment fixes components and has no administrative entry points", async () => {
  const f = await fixture();
  for (const name of ["owner", "setAvailabilityModule", "setLeafDecisionVerifier", "setFhevmVerifier", "setKmsVerdictVerifier"])
    assert.equal(f.game.interface.getFunction(name), null);
  for (const caller of [f.requester, f.operator, f.outsider]) {
    for (const name of ["setAvailabilityModule", "setLeafDecisionVerifier", "setFhevmVerifier", "setKmsVerdictVerifier"])
      await reject(() => caller.sendTransaction({ to: f.game.target,
        data: ethers.concat([ethers.id(`${name}(address)`).slice(0, 10), coder.encode(["address"], [caller.address])]), ...gas }));
  }
  assert.equal(await f.game.availabilityModule(), f.availability.target);
  assert.equal(await f.game.leafDecisionVerifier(), f.verifier.target);
  assert.equal(await f.game.fhevmVerifier(), ethers.ZeroAddress);
  assert.equal(await f.game.kmsVerdictVerifier(), ethers.ZeroAddress);
  assert.equal(await f.verifier.threshold(), 2n);
  assert.equal(f.verifier.interface.getFunction("registerSigner"), null);
  assert.equal(f.verifier.interface.getFunction("setThreshold"), null);
  assert.ok(await f.verifier.isSigner(f.committee[0].address));
  assert.equal(await f.verifier.isSigner(f.outsider.address), false);
  for (const name of ["CanonicalFHEDisputeGame", "LegacyConfigurableDisputeGame", "UniformParticipantSampler"]) {
    const a = f.artifacts[name];
    assert.ok(a.deployedBytecodeBytes <= 24_576);
    assert.ok(ethers.getBytes(a.bytecode).length + 32 * 6 <= 49_152);
  }
  const samplerCode = await f.provider.getCode(await f.game.participantSampler());
  assert.equal(samplerCode, f.artifacts.UniformParticipantSampler.deployedBytecode);
  evidence.runtimeBytes = Object.fromEntries(["CanonicalFHEDisputeGame", "LegacyConfigurableDisputeGame", "UniformParticipantSampler"]
    .map(name => [name, f.artifacts[name].deployedBytecodeBytes]));
});

test("canonical construction rejects modules bound to another game and a one-signer quorum", async () => {
  await fixture({ wrongBinding: true });
  await fixture({ threshold: 1 });
});

test("registrations after the seed is known cannot change either task cohort; future tasks include them", async () => {
  const f = await fixture();
  const { taskId, receipt } = await f.create("frozen-known-hash");
  assert.deepEqual(Array.from(await f.game.getTaskCandidateCounts(taskId)), [4n, 4n]);
  await reject(() => f.game.sampleParticipants(taskId));
  await reject(() => f.game.finalizeUnchallenged(taskId));
  await advanceBlocks(f.provider, 2);
  const seed = (await f.provider.getBlock(receipt.blockNumber + 1)).hash;
  for (const newcomer of f.late) {
    await confirm(f.game.connect(newcomer).registerAuditor(stake));
    await confirm(f.game.connect(newcomer).registerDecryptor(stake));
  }
  // Re-registering an existing identity funds its stake without appending it.
  await confirm(f.game.connect(f.auditors[0]).registerAuditor(stake));
  await record("sampleParticipants", f.game.connect(f.outsider).sampleParticipants(taskId, gas));
  await checkCohorts(f, taskId, seed);
  assert.deepEqual(Array.from(await f.game.getTaskCandidateCounts(taskId)), [4n, 4n]);
  await reject(() => f.game.sampleParticipants(taskId, gas));
  const next = await f.create("future-task-includes-newcomers");
  assert.deepEqual(Array.from(await f.game.getTaskCandidateCounts(next.taskId)), [8n, 8n]);
  await advanceBlocks(f.provider, 2);
  const nextSeed = (await f.provider.getBlock(next.receipt.blockNumber + 1)).hash;
  await record("sampleParticipants", f.game.connect(f.operator).sampleParticipants(next.taskId, gas));
  await checkCohorts(f, next.taskId, nextSeed, [...f.auditors, ...f.late], [...f.openers, ...f.late]);
});

test("expired hashes preserve the original candidate lists through rescheduling", async () => {
  const f = await fixture(), { taskId } = await f.create("frozen-reschedule");
  await advanceBlocks(f.provider, 260);
  const rescheduled = await record("rescheduleParticipants", f.game.connect(f.outsider).sampleParticipants(taskId, gas));
  assert.equal((await f.game.getAssignedAuditors(taskId)).length, 0);
  for (const newcomer of f.late) {
    await confirm(f.game.connect(newcomer).registerAuditor(stake));
    await confirm(f.game.connect(newcomer).registerDecryptor(stake));
  }
  const seed = (await f.provider.getBlock(rescheduled.blockNumber + 1)).hash;
  await record("sampleParticipants", f.game.connect(f.outsider).sampleParticipants(taskId, gas));
  await checkCohorts(f, taskId, seed);
  assert.deepEqual(Array.from(await f.game.getTaskCandidateCounts(taskId)), [4n, 4n]);
});

test("reschedule limit remains three and an unsampled task cannot be accepted", async () => {
  const f = await fixture(), { taskId } = await f.create("bounded-reschedules");
  const cap = Number(await f.game.MAX_SEED_RESCHEDULES());
  assert.equal(cap, 3);
  for (let i = 0; i < cap; i++) {
    await advanceBlocks(f.provider, 260);
    await record("rescheduleParticipants", f.game.connect(f.outsider).sampleParticipants(taskId, gas));
    assert.deepEqual(Array.from(await f.game.getTaskCandidateCounts(taskId)), [4n, 4n]);
  }
  await advanceBlocks(f.provider, 260);
  await reject(() => f.game.connect(f.outsider).sampleParticipants(taskId, gas));
  await advanceTime(f.provider, 61);
  await reject(() => f.game.finalizeUnchallenged(taskId, gas));
  assert.equal(Number((await f.game.getTaskStatus(taskId)).decision), 0);
});

test("stateless sampler preserves deterministic sampling and rejects impossible populations", async () => {
  const f = await fixture();
  const sampler = new ethers.Contract(await f.game.participantSampler(), f.artifacts.UniformParticipantSampler.abi, f.outsider);
  for (const size of [3, 4, 8, 31]) {
    const pool = Array.from({ length: size }, (_, i) => ({ address: ethers.getAddress(ethers.toBeHex(i + 1, 20)) }));
    const task = ethers.id(`sampler-${size}`), seed = ethers.id("sampler-seed");
    const domain = ethers.keccak256(coder.encode(["bytes32", "bytes32", "string"], [task, seed, "auditors"]));
    const indices = await sampler.sampleIndices(size, 3, domain);
    assert.deepEqual(Array.from(indices, i => pool[Number(i)].address), expected(pool, task, seed, "auditors"));
  }
  await reject(() => sampler.sampleIndices(0, 3, ethers.ZeroHash));
  await reject(() => sampler.sampleIndices(2, 3, ethers.ZeroHash));
  await reject(() => sampler.sampleIndices(3, 0, ethers.ZeroHash));
});

test("constructor-fixed canonical game preserves admitted-outage safety and quorum recovery", async () => {
  // Opaque-handle contract fixture: this tests admission and certificates,
  // not actual FHE recomputation or independently administered signers.
  const f = await fixture(), { taskId, plan } = await f.create("canonical-outage-recovery");
  await advanceBlocks(f.provider, 2);
  await confirm(f.game.sampleParticipants(taskId, gas));
  const domain = canonicalDomain(31337, f.verifier.target), contextDigest = ethers.id("context");
  const contextSignatures = await Promise.all(f.committee.slice(0, 2).map(w =>
    w.signTypedData(domain, CONTEXT_TYPES, { taskId, contextDigest })));
  await reject(() => f.verifier.registerContext(taskId, contextDigest, [contextSignatures[0], contextSignatures[0]]));
  await confirm(f.verifier.connect(f.outsider).registerContext(taskId, contextDigest, contextSignatures));
  const assigned = await f.game.getAssignedAuditors(taskId);
  const challenger = f.auditors.find(s => s.address === assigned[0]);
  const challengerLeaf = { ...leaves[0], claimed: 4 }, challengerTree = buildMerkleTree([challengerLeaf]);
  const errorDigest = challengeErrorDigest(taskId, 0, leaves[0], challengerLeaf);
  const transcript = buildAuditTranscript({ taskId, auditorAddress: challenger.address,
    operatorTraceRoot: tree.root, auditTraceLeaf: { leafIndex: 0, operatorLeafHash: leafHash(leaves[0]),
      recomputedLeafHash: leafHash(challengerLeaf), errorDigest }, operatorLeaf: leaves[0], recomputedLeaf: challengerLeaf });
  const commits = [];
  for (const address of assigned) {
    const auditor = f.auditors.find(s => s.address === address), verdict = address !== challenger.address;
    const podRoot = verdict ? ethers.id(`support-${address}`) : transcript.root, salt = ethers.id(`salt-${address}`);
    const commitment = ethers.keccak256(coder.encode(["bytes32", "address", "bool", "bytes32", "bytes32"],
      [taskId, address, verdict, salt, podRoot]));
    await confirm(f.game.connect(auditor).submitAudit(taskId, 0, podRoot, commitment));
    commits.push({ address, verdict, salt, podRoot });
  }
  await advanceTime(f.provider, 21);
  const openerAddresses = (await f.game.getAssignedDecryptors(taskId)).slice(0, 2);
  for (const c of commits) for (const address of openerAddresses) {
    const opener = f.openers.find(s => s.address === address);
    await confirm(f.game.connect(opener).openVerdict(taskId, c.address, c.verdict, c.salt, c.podRoot));
  }
  await confirm(f.game.sealDiligenceRandomness(taskId));
  const checkpoint = selectAuditDiligenceCheckpoint(transcript,
    await f.game.getRequiredDiligenceCheckpointIndex(taskId, challenger.address));
  await confirm(f.game.connect(challenger).proveAuditDiligence(taskId, checkpoint.diligenceCheckpoint,
    checkpoint.diligenceProof, checkpoint.diligenceProofSiblingOnLeft));
  await advanceTime(f.provider, 21);
  await confirm(f.game.connect(challenger).openChallenge(taskId, challengerTree.root, 0, errorDigest,
    transcript.leaves[0], transcript.proof, transcript.proofSiblingOnLeft));
  await confirm(f.availability.connect(f.operator).publishDisputedTraceBatch(taskId,
    plan.disclosureLeaves.map(r => r.leaf), plan.disclosureLeaves.map(r => r.lhsInputProof),
    plan.disclosureLeaves.map(r => r.rhsInputProof), gas));
  const claims = [taskId, traceLeafClaim(leaves[0]), traceLeafClaim(challengerLeaf)];
  await reject(() => f.game.settleLeafViaAttestedDecision(taskId, claims[1],
    { ...claims[2], claimedHandle: ethers.id("uncommitted") }, false, false, "0x", gas));
  await confirm(f.game.connect(f.outsider).settleLeafViaAttestedDecision(...claims, false, false, "0x", gas));
  assert.equal((await f.game.getPendingFhevmLeafResolution(taskId)).active, true);
  const before = await Promise.all([f.operator, challenger].map(s => f.game.getParticipantStake(s.address)));
  await advanceTime(f.provider, 41);
  await reject(() => f.game.timeoutDispute(taskId, gas));
  assert.equal(Number((await f.game.getTaskStatus(taskId)).status), 2);
  assert.equal(Number((await f.game.getTaskStatus(taskId)).decision), 0);
  assert.deepEqual(await Promise.all([f.operator, challenger].map(s => f.game.getParticipantStake(s.address))), before);
  await reject(() => f.game.finalizeUnchallenged(taskId, gas));
  const binding = await f.game.leafDecisionBinding(taskId, 0, leaves[0].opcode);
  const resultHandle = claims[1].claimedHandle;
  const signatures = await Promise.all(f.committee.slice(0, 2).map(w => w.signTypedData(domain, RESULT_TYPES, {
    profileDigest: ethers.id("profile"), contextDigest, leafBinding: ethers.keccak256(binding), resultHandle })));
  const proof = sigs => coder.encode(["bytes[]", "bytes"], [[resultHandle, ...sigs], binding]);
  await reject(() => f.game.settleLeafViaAttestedDecision(...claims, true, false, proof([signatures[0]]), gas));
  await reject(() => f.game.settleLeafViaAttestedDecision(...claims, true, false, proof([signatures[0], signatures[0]]), gas));
  await record("settleCanonicalLeaf", f.game.connect(f.outsider).settleLeafViaAttestedDecision(
    ...claims, true, false, proof(signatures), gas));
  assert.equal(Number((await f.game.getTaskStatus(taskId)).status), 1);
  await advanceTime(f.provider, 61);
  await confirm(f.game.finalizeUnchallenged(taskId, gas));
  assert.equal(Number((await f.game.getTaskStatus(taskId)).decision), 1);
});

test("canonical driver deploys the fixed stack without administrative wiring transactions", async () => {
  const provider = await createProvider({ totalAccounts: 12 });
  const signers = await Promise.all(Array.from({ length: 12 }, (_, i) => signerFor(provider, i)));
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "canonical-deployment-test-"));
  try {
    const stack = await createCanonicalGame({ provider, signers, context: { profile: { fixture: true } }, workDir,
      publicDir: workDir, binary: "unused-deployment-fixture", rpcUrl: "unused", advanceSeconds: async () => {} });
    const labels = stack.txs.map(r => r.label);
    assert.ok(labels.includes("deploy:CanonicalFHEDisputeGame"));
    assert.ok(labels.every(label => !label.startsWith("set")));
    assert.equal(await stack.game.availabilityModule(), stack.availability.target);
    assert.equal(await stack.game.leafDecisionVerifier(), stack.verifier.target);
    assert.equal(await stack.verifier.game(), stack.game.target);
    assert.equal(await stack.availability.game(), stack.game.target);
  } finally { await fs.rm(workDir, { recursive: true }); }
});

after(async () => {
  const file = process.env.VCFHE_ASSIGNMENT_EVIDENCE;
  if (!file) return;
  evidence.sourceHashes = {};
  for (const name of ["VerifiableFHEDisputeGame", "CanonicalFHEDisputeGame", "LegacyConfigurableDisputeGame", "UniformParticipantSampler", "CanonicalLeafVerifier", "AuthenticatedTraceAvailability"])
    evidence.sourceHashes[`${name}.sol`] = createHash("sha256").update(await fs.readFile(new URL(`../src/${name}.sol`, import.meta.url))).digest("hex");
  await fs.writeFile(file, JSON.stringify(evidence, null, 2) + "\n", { flag: "wx" });
});
