import fs from "node:fs/promises";
import assert from "node:assert/strict";
import { prepareSealedBountyAudit, authenticatedBountyBatch, bountyRelayBatchSize } from "./canonical-bounty-client.mjs";
import { BOUNTY_TEST_ECONOMICS } from "./bounty-economics.mjs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ethers, compileContracts, boundCreateTaskArgs, terminalOutputBinding,
  sampleTaskParticipants, buildAuditTranscript, challengeErrorDigest, leafHash,
  selectAuditDiligenceCheckpoint, getSubtreeChildren, traceLeafClaim } from "./evm-lib.mjs";
import { canonicalTrace, hashJson } from "./canonical-protocol.mjs";
import { publicTracePlan, outputArtifactDigest } from "./canonical-chain.mjs";
const here = path.dirname(fileURLToPath(import.meta.url));
// Batching changes transaction overhead, not the authenticated disclosure rule.
// The Test dataset profile permits at most 64. Bounty relays additionally
// cap each transaction's prefix through bountyRelayBatchSize.
export function canonicalDisclosureBatches(rows, size = 8) {
  if (!Number.isSafeInteger(size) || size < 1 || size > 64) throw new Error("disclosure batch size must be an integer in [1,64]");
  const batches = [];
  for (let start = 0; start < rows.length; start += size) batches.push(rows.slice(start, start + size));
  return batches;
}
export function canonicalAuditorFunding(leafCount, minimumStake, baseBond, perRoundBond, slashAmount) {
  if (!Number.isSafeInteger(leafCount) || leafCount < 1 || leafCount > 2 ** 31 ||
      !Number.isInteger(Math.log2(leafCount))) throw new Error("funding requires a positive power-of-two leaf count");
  const values = [minimumStake, baseBond, perRoundBond, slashAmount].map(BigInt);
  if (values.some(v => v < 0n)) throw new Error("negative collateral parameter");
  const [minimum, base, perRound, slash] = values;
  return [minimum, slash, base + BigInt(Math.log2(leafCount)) * perRound].reduce((a, b) => a > b ? a : b);
}
function safeTimestamp(value) {
  if (value === null || value === undefined ||
      !["bigint", "number", "string"].includes(typeof value)) throw new Error("invalid on-chain timestamp");
  let parsed;
  try { parsed = typeof value === "bigint" ? value : BigInt(value); }
  catch { throw new Error("invalid on-chain timestamp"); }
  if (parsed < 0n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("invalid on-chain timestamp");
  return Number(parsed);
}
export async function freshChainTimestamp(provider, { maxAttempts = 20, retryDelayMs = 250 } = {}) {
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 ||
      !Number.isSafeInteger(retryDelayMs) || retryDelayMs < 0) throw new Error("invalid latest-block retry limits");
  const rawRpc = typeof provider?.send === "function";
  if (!rawRpc && typeof provider?.getBlock !== "function") throw new Error("provider cannot read the latest block");
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const block = rawRpc
      ? await provider.send("eth_getBlockByNumber", ["latest", false])
      : await provider.getBlock("latest");
    if (block !== null && block !== undefined && block.timestamp !== null && block.timestamp !== undefined)
      return safeTimestamp(block.timestamp);
    if (attempt < maxAttempts && retryDelayMs) await new Promise(resolve => setTimeout(resolve, retryDelayMs));
  }
  throw new Error("latest block unavailable within bounded retries");
}
export async function advancePastDeadline(provider, advanceSeconds, deadline) {
  const now = await freshChainTimestamp(provider), target = safeTimestamp(deadline);
  // The second argument is the absolute chain timestamp required by the
  // protocol. Real-chain callers must wait for this value directly: deriving a
  // new target from a later block would slide the deadline. Development-chain
  // callbacks may continue to use the first, relative argument.
  if (now <= target) await advanceSeconds(target - now + 1, target + 1);
  const observedAt = await freshChainTimestamp(provider);
  if (observedAt <= target)
    throw new Error("chain did not advance past the on-chain deadline");
  return { deadline: target, observedTimestamp: observedAt };
}
export async function signingWorker(request) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(here, "canonical-attester.mjs")], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "", error = "";
    child.stdout.on("data", b => { out += b; }); child.stderr.on("data", b => { error += b; });
    child.on("error", reject); child.on("close", code => {
      if (code !== 0) reject(new Error(`public attester failed: ${error.slice(-3000)}`));
      else { try { resolve(JSON.parse(out)); } catch (e) { reject(e); } }
    }); child.stdin.end(JSON.stringify(request));
  });
}
export async function createCanonicalGame({ provider, signers, context, binary, publicDir, workDir, rpcUrl,
  advanceSeconds, windowSeconds = 200, disclosureBatchSize = 8, auditorFundingLeafCount, receipt,
  nonlinearProtocol = "canonical", workerRunner = signingWorker }) {
  if (!["canonical", "bounty-v2"].includes(nonlinearProtocol)) throw new Error("unknown nonlinear protocol");
  const bountyV2 = nonlinearProtocol === "bounty-v2";
  if (bountyV2 && auditorFundingLeafCount > BOUNTY_TEST_ECONOMICS.maxTraceLeaves)
    throw new Error("trace exceeds the bounty deployment cost budget");
  const gameName = bountyV2 ? "CanonicalBountyFHEDisputeGame" : "CanonicalFHEDisputeGame";
  const availabilityName = bountyV2 ? "BountyTraceAvailability" : "AuthenticatedTraceAvailability";
  canonicalDisclosureBatches([], disclosureBatchSize); // Reject before deployment.
  if (auditorFundingLeafCount !== undefined) canonicalAuditorFunding(auditorFundingLeafCount, 0n, 0n, 0n, 0n);
  const artifacts = await compileContracts();
  const [requester, operator, ...rest] = signers;
  const auditors = rest.slice(0, 3), openingParticipants = rest.slice(3, 6);
  const identities = Array.from({ length: 3 }, () => ethers.Wallet.createRandom());
  const txs = [];
  const record = async (label, promise) => {
    const tx = await promise, r = await tx.wait();
    const row = { label, txHash: r.hash, gasUsed: r.gasUsed.toString(), blockNumber: r.blockNumber,
      status: r.status, from: r.from, to: r.to,
      ...(bountyV2 ? { logs: r.logs.map(l => ({ address: l.address, topics: Array.from(l.topics), data: l.data })) } : {}) };
    txs.push(row); receipt?.(row); if (r.status !== 1) throw new Error(`${label} reverted`); return r;
  };
  const deploy = async (name, args = []) => {
    const c = await new ethers.ContractFactory(artifacts[name].abi, artifacts[name].bytecode, requester).deploy(...args);
    await record(`deploy:${name}`, c.deploymentTransaction()); return c;
  };
  const objective = await deploy("ObjectiveMicroVerifier");
  // Modules bind to the game before it is deployed. Constructor checks make
  // an intervening transaction from this account fail closed, not miswire it.
  const nonce = BigInt(await provider.send("eth_getTransactionCount", [await requester.getAddress(), "pending"]));
  const gameAddress = ethers.getCreateAddress({ from: await requester.getAddress(), nonce: nonce + 2n });
  const availability = await deploy(availabilityName, [gameAddress, windowSeconds]);
  const verifier = await deploy("CanonicalLeafVerifier", [gameAddress, hashJson(context.profile), identities.map(s => s.address), 2]);
  const game = await deploy(gameName, [objective.target, windowSeconds, windowSeconds, windowSeconds,
    availability.target, verifier.target, ...(bountyV2 ? BOUNTY_TEST_ECONOMICS.extraConstructorArgs : [])]);
  const operatorStake = bountyV2 ? ethers.parseEther("2") + BigInt(BOUNTY_TEST_ECONOMICS.operatorPenaltyWei) : ethers.parseEther("2");
  await record("registerOperator", game.connect(operator).registerOperator({ value: operatorStake }));
  // Fund the actual application trace from the deployed rule before any timed
  // task starts. Legacy callers retain their original one-ether fixture.
  const auditorStake = auditorFundingLeafCount === undefined ? ethers.parseEther("1") :
    canonicalAuditorFunding(auditorFundingLeafCount, ...await Promise.all([
      game.MIN_AUDITOR_STAKE_WEI(), game.DISPUTE_BOND_BASE_WEI(),
      game.DISPUTE_BOND_PER_ROUND_WEI(), game.SLASH_AMOUNT_WEI()]));
  for (const a of auditors) await record("registerAuditor", game.connect(a).registerAuditor({ value: auditorStake }));
  for (const a of bountyV2 ? [] : openingParticipants) await record("registerOpeningParticipant", game.connect(a).registerDecryptor({ value: ethers.parseEther("1") }));
  const contextFile = path.join(workDir, "context.json"); await fs.writeFile(contextFile, JSON.stringify(context));
  const identityFiles = [];
  for (let i = 0; i < identities.length; i++) {
    const f = path.join(workDir, `attester-${i}.key`);
    await fs.writeFile(f, identities[i].privateKey, { mode: 0o600, flag: "wx" }); identityFiles.push(f);
  }
  const worker = (mode, taskId, operatorDir, extra = {}) => Promise.all(identityFiles.slice(0, 2).map((identityFile, i) =>
    workerRunner({ mode, taskId, operatorDir, game: game.target, rpcUrl, contextFile, identityFile,
      binary, publicDir, ...extra, replayDir: path.join(workDir, `full-${taskId}-${i}-${Date.now()}`),
      outputFile: path.join(workDir, `leaf-${taskId}-${i}-${Date.now()}.ct`) })));
  const byAddress = (list, address) => list.find(a => a.address.toLowerCase() === address.toLowerCase());
  const created = new Map();
  async function createTask(taskId, operatorDir) {
    const trace = await canonicalTrace(context, publicDir, operatorDir);
    const { leaves, plan } = publicTracePlan(taskId, context, trace.manifest);
    const ownerGroups = new Map();
    for (const r of plan.inputRecords) {
      const ownerAddress = context.inputs[r.sourceIndex]?.owner ?? context.inputs[0].owner;
      const group = ownerGroups.get(ownerAddress) ?? []; group.push(r); ownerGroups.set(ownerAddress, group);
    }
    for (const [address, rows] of ownerGroups) {
      const owner = byAddress(signers, address); if (!owner) throw new Error("owner signing identity unavailable");
      await record("registerInputOrigins", availability.connect(owner).registerInputOrigins(rows.map(r => r.ciphertextHandle), rows.map(r => r.metadataHash)));
    }
    const artifact = outputArtifactDigest(context, trace.manifest.terminalHandle);
    const binding = terminalOutputBinding(taskId, trace.tree, leaves, artifact);
    const latest = await provider.getBlock("latest");
    await record("authorizeTaskStatement", availability.connect(requester).authorizeTaskStatement(taskId, operator.address,
      trace.tree.root, binding.resultHash, plan.inputTree.root, plan.inputTree.leafCount,
      plan.programTree.root, plan.provenanceTree.root, leaves.length, artifact, latest.timestamp + 86400));
    await record("createTask", game.connect(operator).createTask(...boundCreateTaskArgs(taskId, trace.tree, leaves, artifact)));
    const certificates = await worker("context", taskId, operatorDir);
    await record("registerCanonicalContext", verifier.registerContext(taskId, hashJson(context), certificates.map(c => c.signature)));
    // The helper also advances a development chain's assignment block.
    const sample = await sampleTaskParticipants(game, taskId);
    const sampleRow = { label: "sampleParticipants", txHash: sample.hash, gasUsed: sample.gasUsed.toString(),
      blockNumber: sample.blockNumber, status: sample.status, from: sample.from, to: sample.to };
    txs.push(sampleRow); receipt?.(sampleRow);
    const result = { trace, leaves, plan, operatorDir }; created.set(taskId, result); return result;
  }
  async function discloseBeforeAudit(taskId) {
    if (!bountyV2) return undefined;
    const op = created.get(taskId), first = (await game.getAssignedAuditors(taskId))[0];
    const auditor = byAddress(auditors, first), start = txs.length;
    const bond = await availability.requiredDisclosureBond(taskId);
    await record("requestBountyTraceDisclosure", availability.connect(auditor).requestTraceDisclosure(taskId, { value: bond }));
    const task = { taskId, operatorTree: op.trace.tree, plan: op.plan };
    let splits = 0;
    while (Number(await availability.nextDisclosureIndex(taskId)) < op.leaves.length) {
      const args = await authenticatedBountyBatch({ availability, task, count: bountyRelayBatchSize(disclosureBatchSize) });
      splits += args[4].length;
      await record("publishAuthenticatedTraceBatch", availability.connect(requester).publishAuthenticatedTraceBatch(...args, { gasLimit: 20_000_000 }));
    }
    const disclosureDeadline = await availability.disclosureDeadline(taskId);
    const [commitDeadline] = await game.getTaskDeadlines(taskId);
    assert.ok(commitDeadline >= disclosureDeadline + BigInt(windowSeconds), "missing full replay window after disclosure");
    assert.equal(splits, op.leaves.length - 1, "wrong authenticated frontier split count");
    op.disclosure = { requester: auditor.address, recipient: operator.address,
      requestBondWei: String(bond), disclosureDeadline: String(disclosureDeadline),
      commitDeadline: String(commitDeadline), splits, receipts: txs.slice(start).map(r => r.txHash) };
    return op.disclosure;
  }
  async function auditAndChallenge(taskId, detection, replayDir, { afterAdmission } = {}) {
    if (detection.index === null) throw new Error("cannot challenge an identical replay");
    const index = detection.index, op = created.get(taskId);
    const chTrace = await canonicalTrace(context, publicDir, replayDir);
    if (detection.operatorRoot !== op.trace.tree.root || detection.replayRoot !== chTrace.tree.root) throw new Error("detection root mismatch");
    const chLeaves = publicTracePlan(taskId, context, chTrace.manifest).leaves;
    const challenger = byAddress(auditors, (await game.getAssignedAuditorsForLeaf(taskId, index))[0]);
    const errorDigest = challengeErrorDigest(taskId, index, op.leaves[index], chLeaves[index]);
    const transcript = buildAuditTranscript({ taskId, auditorAddress: challenger.address,
      operatorTraceRoot: op.trace.tree.root,
      auditTraceLeaf: { leafIndex: index, operatorLeafHash: leafHash(op.leaves[index]), recomputedLeafHash: leafHash(chLeaves[index]), errorDigest },
      operatorLeaf: op.leaves[index], recomputedLeaf: chLeaves[index] });
    const commitments = [];
    if (bountyV2) {
      assert.ok(op.disclosure, "bounty campaign must disclose before full replay");
      for (const address of await game.getAssignedAuditors(taskId)) {
        const auditor = byAddress(auditors, address), dissent = address.toLowerCase() === challenger.address.toLowerCase();
        // Nonchallengers are adversarial agreement controls, never rewarded or
        // described as independent full replays in the cost report.
        const audit = await prepareSealedBountyAudit({ game, taskId, auditorAddress: address,
          operatorLeaves: op.leaves, candidateLeaves: dissent ? chLeaves : op.leaves, index, supportsOperator: !dissent });
        await record("submitSealedAudit", game.connect(auditor).submitSealedAudit(taskId, audit.commitment));
        commitments.push({ auditor, audit });
      }
    } else {
      for (const address of await game.getAssignedAuditors(taskId)) {
        const auditor = byAddress(auditors, address), dissent = address.toLowerCase() === challenger.address.toLowerCase();
        const podRoot = dissent ? transcript.root : ethers.id(`adversarial-opinion-${taskId}-${address}`);
        const salt = ethers.hexlify(ethers.randomBytes(32)), verdict = !dissent;
        const commitment = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "address", "bool", "bytes32", "bytes32"], [taskId, auditor.address, verdict, salt, podRoot]));
        let assignedIndex = index;
        if (!await game.isAuditorAssignedToLeaf(taskId, address, index)) {
          for (let j = 0; j < op.leaves.length; j++) if (await game.isAuditorAssignedToLeaf(taskId, address, j)) { assignedIndex = j; break; }
        }
        await record("submitAudit", game.connect(auditor).submitAudit(taskId, assignedIndex, podRoot, commitment));
        commitments.push({ auditor, verdict, salt, podRoot });
      }
    }
    const [commitDeadline, openDeadline] = await game.getTaskDeadlines(taskId);
    await advancePastDeadline(provider, advanceSeconds, commitDeadline);
    if (bountyV2) {
      for (const c of commitments) await record("revealSealedAudit", game.connect(requester).revealSealedAudit(...c.audit.opening, { gasLimit: 5_000_000 }));
    } else {
      const openers = (await game.getAssignedDecryptors(taskId)).slice(0, 2).map(a => byAddress(openingParticipants, a));
      for (const c of commitments) for (const opener of openers) await record("openVerdict", game.connect(opener).openVerdict(taskId, c.auditor.address, c.verdict, c.salt, c.podRoot));
    }
    await record("sealDiligenceRandomness", game.sealDiligenceRandomness(taskId));
    const checkpoint = selectAuditDiligenceCheckpoint(transcript, await game.getRequiredDiligenceCheckpointIndex(taskId, challenger.address));
    await record("proveAuditDiligence", game.connect(challenger).proveAuditDiligence(taskId, checkpoint.diligenceCheckpoint, checkpoint.diligenceProof, checkpoint.diligenceProofSiblingOnLeft));
    await advancePastDeadline(provider, advanceSeconds, openDeadline);
    await record("openChallenge", game.connect(challenger).openChallenge(taskId, chTrace.tree.root, index, errorDigest,
      transcript.leaves[0], transcript.proof, transcript.proofSiblingOnLeft));
    for (const rows of bountyV2 ? [] : canonicalDisclosureBatches(op.plan.disclosureLeaves, disclosureBatchSize)) {
      await record("publishDisputedTraceBatch", availability.connect(operator).publishDisputedTraceBatch(taskId,
        rows.map(r => r.leaf), rows.map(r => r.lhsInputProof), rows.map(r => r.rhsInputProof), { gasLimit: 20_000_000 }));
    }
    let state = await game.getTaskDisputeState(taskId);
    while (Number(state.disputeEnd - state.disputeStart) > 1) {
      const args = [Number(state.disputeStart), Number(state.disputeEnd)];
      const o = getSubtreeChildren(op.trace.tree, ...args), c = getSubtreeChildren(chTrace.tree, ...args);
      await record(bountyV2 ? "relayOperatorBisection" : "operatorBisection", game.connect(bountyV2 ? requester : operator).submitBisection(taskId, true, o.left, o.right, { gasLimit: 5_000_000 }));
      await record(bountyV2 ? "relayChallengerBisection" : "challengerBisection", game.connect(bountyV2 ? requester : challenger).submitBisection(taskId, false, c.left, c.right, { gasLimit: 5_000_000 }));
      await record("advanceDispute", game.advanceDispute(taskId, { gasLimit: 5_000_000 }));
      state = await game.getTaskDisputeState(taskId);
    }
    if (Number(state.disputeStart) !== index) throw new Error("chain isolated another leaf");
    const claimArgs = [taskId, traceLeafClaim(op.leaves[index]), traceLeafClaim(chLeaves[index])];
    await record("admitCanonicalLeaf", game.settleLeafViaAttestedDecision(...claimArgs, false, false, "0x", { gasLimit: 5_000_000 }));
    await afterAdmission?.({ game, taskId, claimArgs });
    const certificates = await worker("leaf", taskId, op.operatorDir, { challengerLeaf: claimArgs[2], leafIndex: index });
    if (new Set(certificates.map(c => c.evidence.recomputedHandle)).size !== 1) throw new Error("independent canonical attesters disagree");
    const evidence = certificates[0].evidence;
    const binding = await game.leafDecisionBinding(taskId, index, op.leaves[index].opcode);
    const proof = ethers.AbiCoder.defaultAbiCoder().encode(["bytes[]", "bytes"], [[evidence.recomputedHandle, ...certificates.map(c => c.signature)], binding]);
    const settleArgs = [...claimArgs, evidence.operatorValid, evidence.challengerValid, proof];
    // Duplicate/subquorum and altered-result certificates must fail on chain.
    const coder = ethers.AbiCoder.defaultAbiCoder();
    for (const signatures of [[evidence.recomputedHandle, certificates[0].signature],
      [evidence.recomputedHandle, certificates[0].signature, certificates[0].signature],
      [ethers.id("wrong-public-result"), ...certificates.map(c => c.signature)]]) {
      const forged = coder.encode(["bytes[]", "bytes"], [signatures, binding]);
      let rejected = false;
      try { await game.settleLeafViaAttestedDecision.staticCall(...claimArgs, evidence.operatorValid, evidence.challengerValid, forged); }
      catch { rejected = true; }
      if (!rejected) throw new Error("forged canonical certificate accepted");
    }
    const parties = [operator, ...auditors];
    const before = bountyV2 ? await Promise.all(parties.map(s => game.getParticipantStake(s.address))) : [];
    const settlementReceipt = await record("settleCanonicalLeaf", game.settleLeafViaAttestedDecision(...settleArgs, { gasLimit: 5_000_000 }));
    let bounty;
    if (bountyV2) {
      assert.equal(evidence.operatorValid, false); assert.equal(evidence.challengerValid, true);
      const penalty = await game.OPERATOR_PENALTY_WEI(), reward = await game.CHALLENGE_BOUNTY_WEI();
      const after = await Promise.all(parties.map(s => game.getParticipantStake(s.address)));
      for (let i = 0; i < parties.length; i++)
        assert.equal(after[i], before[i] + (i === 0 ? -penalty : parties[i].address === challenger.address ? reward : 0n));
      assert.equal(await game.getOperatorReservation(taskId), 0n);
      assert.equal(await game.getAuditReservation(taskId, challenger.address), 0n);
      for (const c of commitments) if (c.auditor.address !== challenger.address)
        await record("claimUnusedAuditBond", game.connect(c.auditor).claimAuditBond(taskId));
      // Use a separate destination so its balance delta excludes the sender's gas.
      const destination = requester.address;
      const readBalance = () => provider.send("eth_getBalance", [destination, "latest"]).then(BigInt);
      const balanceBefore = await readBalance();
      const withdrawal = await record("withdrawChallengeBounty", game.connect(challenger).withdraw(reward, destination));
      const received = await readBalance() - balanceBefore;
      assert.equal(received, reward);
      const settlement = settlementReceipt.logs.map(l => { try { return game.interface.parseLog(l); } catch { return null; } })
        .find(l => l?.name === "BountySettlement");
      assert.ok(settlement); assert.equal(settlement.args.bountyWei, reward);
      bounty = { protocol: nonlinearProtocol, taskId, operator: operator.address, challenger: challenger.address,
        relayer: requester.address, game: game.target, availability: availability.target,
        parties: parties.map(s => s.address), stakesBefore: before.map(String), stakesAfter: after.map(String),
        penaltyWei: String(penalty), rewardWei: String(reward), burnedWei: String(settlement.args.burnedWei),
        withdrawalWei: String(received), settlementTx: settlementReceipt.hash, withdrawalTx: withdrawal.hash,
        disclosure: op.disclosure };
    }
    return { index, certificates, settleArgs, ...(bounty ? { bounty } : {}), state: Array.from(await game.getTaskStatus(taskId)).map(v => typeof v === "bigint" ? Number(v) : v) };
  }
  return { game, availability, verifier, record, txs, identities, createTask, auditAndChallenge, discloseBeforeAudit,
    async fullExecutionBaseline(taskId) {
      const baseline = await deploy("CanonicalExecutionBaseline", [verifier.target]);
      const started = performance.now();
      const certificates = await worker("full",taskId,created.get(taskId).operatorDir,{baseline:baseline.target});
      const fullReplayWallMs = performance.now()-started;
      const binding = await game.getTaskResultBinding(taskId);
      let rejected=false;
      try { await baseline.accept.staticCall(taskId,binding.operatorTraceRoot,binding.resultHash,[certificates[0].signature,certificates[0].signature]); }
      catch { rejected=true; }
      if(!rejected)throw new Error("duplicate full-execution certificate accepted");
      await record("acceptFullExecution",baseline.accept(taskId,binding.operatorTraceRoot,binding.resultHash,certificates.map(c=>c.signature)));
      return {fullReplayWallMs,certificates,contract:baseline.target,accepted:await baseline.accepted(taskId)};
    },
    async acceptHonest(taskId, { duringFinalizationWait } = {}) {
      if (duringFinalizationWait !== undefined && (!bountyV2 || typeof duringFinalizationWait !== "function"))
        throw new Error("finalization-wait work requires bounty V2 and an awaited callback");
      let agreement;
      if (bountyV2) {
        const op = created.get(taskId), auditor = byAddress(auditors, (await game.getAssignedAuditors(taskId))[0]);
        // Called only after the controller has completed and compared a full replay.
        const audit = await prepareSealedBountyAudit({ game, taskId, auditorAddress: auditor.address,
          operatorLeaves: op.leaves, candidateLeaves: op.leaves, index: 0, supportsOperator: true });
        const stake = await game.getParticipantStake(auditor.address);
        const commitmentReceipt = await record("honestSubmitSealedAudit", game.connect(auditor).submitSealedAudit(taskId, audit.commitment));
        const [commitDeadline, openDeadline] = await game.getTaskDeadlines(taskId);
        await advancePastDeadline(provider, advanceSeconds, commitDeadline);
        const openingReceipt = await record("honestRevealSealedAudit", game.connect(requester).revealSealedAudit(...audit.opening, { gasLimit: 5_000_000 }));
        agreement = { auditor, stake, commitmentReceipt, openingReceipt, commitDeadline, openDeadline };
      }
      const [, , challengeDeadline] = await game.getTaskDeadlines(taskId);
      let finalizationWaitWork;
      if (duringFinalizationWait) {
        // Mandatory commitment and opening are already confirmed. Run the
        // comparison sequentially, without occupying the auditor's deadline.
        // Overrunning finality only delays finalization, never extends a phase.
        const startTimestamp = await freshChainTimestamp(provider), started = performance.now();
        await duringFinalizationWait();
        const elapsedMs = performance.now() - started;
        finalizationWaitWork = { elapsedMs, startTimestamp,
          endTimestamp: await freshChainTimestamp(provider), challengeDeadline: safeTimestamp(challengeDeadline) };
      }
      await advancePastDeadline(provider, advanceSeconds, challengeDeadline);
      await record("finalizeUnchallenged", game.finalizeUnchallenged(taskId));
      if (agreement) {
        await record("honestClaimAuditBond", game.connect(agreement.auditor).claimAuditBond(taskId));
        assert.equal(await game.getParticipantStake(agreement.auditor.address), agreement.stake, "agreement earns no bounty");
        assert.equal(await game.getOperatorReservation(taskId), 0n);
      }
      if (finalizationWaitWork) {
        // Record actual inclusion margins for the later readiness review. These
        // observations never authorize shorter windows or change acceptance.
        const committed = await provider.getBlock(agreement.commitmentReceipt.blockNumber);
        const opened = await provider.getBlock(agreement.openingReceipt.blockNumber);
        Object.assign(finalizationWaitWork, { commitDeadline: safeTimestamp(agreement.commitDeadline),
          openDeadline: safeTimestamp(agreement.openDeadline), commitTimestamp: safeTimestamp(committed.timestamp),
          openTimestamp: safeTimestamp(opened.timestamp) });
        return { finalizationWaitWork };
      }
    },
    runtimeBytes: ethers.getBytes(await provider.getCode(game.target)).length };
}
