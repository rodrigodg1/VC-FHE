import path from "node:path";
import ganache from "ganache";
import { ethers } from "ethers";
import {
  boundCreateTaskArgs,
  sampleTaskParticipants,
  buildAuditTranscript,
  buildMerkleTree,
  challengeErrorDigest,
  compileContracts,
  getSubtreeChildren,
  leafHash,
  loadRunArtifacts,
  logStep,
  mutateLeafClaim,
  selectAuditDiligenceCheckpoint,
  traceLeafClaim,
  writeJson
} from "./evm-lib.mjs";

const mnemonic = "test test test test test test test test test test test junk";
const chainId = 31337;

async function walletAt(index, provider) {
  return provider.getSigner(index);
}

async function firstAssignedLeaf(contract, taskId, auditor, leafCount, preferred = 0) {
  if (await contract.isAuditorAssignedToLeaf(taskId, auditor.address, preferred)) {
    return preferred;
  }
  for (let leafIndex = 0; leafIndex < leafCount; leafIndex += 1) {
    if (await contract.isAuditorAssignedToLeaf(taskId, auditor.address, leafIndex)) {
      return leafIndex;
    }
  }
  throw new Error(`No assigned leaf for auditor ${auditor.address}`);
}

async function commitAudit(
  contract,
  taskId,
  auditor,
  verdict,
  podRoot,
  auditedLeafIndex,
  leafCount
) {
  const resolvedAuditedLeafIndex =
    auditedLeafIndex ??
    (await firstAssignedLeaf(contract, taskId, auditor, leafCount));
  const salt = ethers.keccak256(
    ethers.toUtf8Bytes(`${taskId}:${auditor.address}:${verdict}:${podRoot}`)
  );
  const verdictCommit = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bool", "bytes32", "bytes32"],
      [verdict, salt, podRoot]
    )
  );

  await (
    await contract
      .connect(auditor)
      .submitAudit(taskId, resolvedAuditedLeafIndex, podRoot, verdictCommit)
  ).wait();
  return { salt, podRoot, verdict, auditedLeafIndex: resolvedAuditedLeafIndex };
}

async function openCommittedAudit(contract, taskId, auditor, auditCommitment, decryptors) {
  for (const decryptor of decryptors) {
    const tx = await contract
      .connect(decryptor)
      .openVerdict(
        taskId,
        auditor.address,
        auditCommitment.verdict,
        auditCommitment.salt,
        auditCommitment.podRoot
      );
    await tx.wait();
  }
}

async function runDispute(
  contract,
  taskId,
  operatorWallet,
  challengerWallet,
  operatorTree,
  challengerTree,
  operatorLeaf,
  challengerLeaf
) {
  let dispute = await contract.getTaskDisputeState(taskId);

  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);

    const operatorChildren = getSubtreeChildren(operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challengerTree, start, end);

    await (
      await contract
        .connect(operatorWallet)
        .submitBisection(taskId, true, operatorChildren.left, operatorChildren.right)
    ).wait();
    await (
      await contract
        .connect(challengerWallet)
        .submitBisection(taskId, false, challengerChildren.left, challengerChildren.right)
    ).wait();
    await (await contract.advanceDispute(taskId)).wait();
    dispute = await contract.getTaskDisputeState(taskId);
  }

  await (
    // Only the opcode and the three ciphertext handles cross the ABI.
    await contract.resolveLeafDispute(
      taskId,
      traceLeafClaim(operatorLeaf),
      traceLeafClaim(challengerLeaf)
    )
  ).wait();
}

const provider = new ethers.BrowserProvider(
  ganache.provider({
    logging: { quiet: true },
    chain: { chainId },
    wallet: {
      mnemonic,
      totalAccounts: 12
    }
  })
);

const deployer = await walletAt(0, provider);
const operator = await walletAt(1, provider);
const challengerCandidate = await walletAt(2, provider);
const auditor3 = await walletAt(3, provider);
const auditor4 = await walletAt(4, provider);
const decryptor1 = await walletAt(5, provider);
const decryptor2 = await walletAt(6, provider);
const decryptor3 = await walletAt(7, provider);

const artifacts = await compileContracts();
const verifierFactory = new ethers.ContractFactory(
  artifacts.ObjectiveMicroVerifier.abi,
  artifacts.ObjectiveMicroVerifier.bytecode,
  deployer
);
const verifier = await verifierFactory.deploy();
await verifier.waitForDeployment();

const gameFactory = new ethers.ContractFactory(
  artifacts.LegacyConfigurableDisputeGame.abi,
  artifacts.LegacyConfigurableDisputeGame.bytecode,
  deployer
);
const game = await gameFactory.deploy(await verifier.getAddress(), 20, 20, 20, false);
await game.waitForDeployment();

logStep("contracts deployed", {
  verifier: await verifier.getAddress(),
  game: await game.getAddress()
});

for (const [label, wallet, fn] of [
  ["operator", operator, "registerOperator"],
  ["auditor-1", challengerCandidate, "registerAuditor"],
  ["auditor-2", auditor3, "registerAuditor"],
  ["auditor-3", auditor4, "registerAuditor"],
  ["decryptor-1", decryptor1, "registerDecryptor"],
  ["decryptor-2", decryptor2, "registerDecryptor"],
  ["decryptor-3", decryptor3, "registerDecryptor"]
]) {
  const stake = label.startsWith("operator")
    ? ethers.parseEther("2")
    : ethers.parseEther("1");
  await (await game.connect(wallet)[fn]({ value: stake })).wait();
}

const { runDir, attestationPayload, microTraceBundle } = await loadRunArtifacts();
const correctLeaves = microTraceBundle.witnesses;
const correctTree = buildMerkleTree(correctLeaves);
const badLeafIndex = 4;
const badLeaves = [...correctLeaves];
badLeaves[badLeafIndex] = mutateLeafClaim(correctLeaves[badLeafIndex], {
  claimed: Number(correctLeaves[badLeafIndex].claimed) + 1
});
const badTree = buildMerkleTree(badLeaves);
const outputAttestationHash = attestationPayload.result_hash_sha256.startsWith("0x")
  ? attestationPayload.result_hash_sha256
  : `0x${attestationPayload.result_hash_sha256}`;

const optimisticTaskId = ethers.encodeBytes32String("task-good");
await (
  await game
    .connect(operator)
    .createTask(
      ...boundCreateTaskArgs(optimisticTaskId, correctTree, correctLeaves, outputAttestationHash)
    )
).wait();
await sampleTaskParticipants(game, optimisticTaskId);

const optimisticAuditors = (await game.getAssignedAuditors(optimisticTaskId)).map((address) =>
  [challengerCandidate, auditor3, auditor4].find(
    (wallet) => wallet.address.toLowerCase() === address.toLowerCase()
  )
);
const optimisticDecryptors = (await game.getAssignedDecryptors(optimisticTaskId)).map((address) =>
  [decryptor1, decryptor2, decryptor3].find(
    (wallet) => wallet.address.toLowerCase() === address.toLowerCase()
  )
);

const optimisticCommitments = [];
for (const auditor of optimisticAuditors) {
  optimisticCommitments.push(
    await commitAudit(
      game,
      optimisticTaskId,
      auditor,
      true,
      ethers.keccak256(ethers.toUtf8Bytes(`pod:optimistic:${auditor.address}`)),
      undefined,
      correctTree.leafCount
    )
  );
}

await provider.send("evm_increaseTime", [21]);
await provider.send("evm_mine", []);
for (let index = 0; index < optimisticAuditors.length; index += 1) {
  await openCommittedAudit(
    game,
    optimisticTaskId,
    optimisticAuditors[index],
    optimisticCommitments[index],
    optimisticDecryptors.slice(0, 2)
  );
}
await provider.send("evm_increaseTime", [41]);
await provider.send("evm_mine", []);
await (await game.finalizeUnchallenged(optimisticTaskId)).wait();
const optimisticTask = await game.getTaskStatus(optimisticTaskId);

const challengedTaskId = ethers.encodeBytes32String("task-bad");
await (
  await game
    .connect(operator)
    .createTask(
      ...boundCreateTaskArgs(challengedTaskId, badTree, badLeaves, outputAttestationHash)
    )
).wait();
await sampleTaskParticipants(game, challengedTaskId);

const challengedAuditors = (await game.getAssignedAuditors(challengedTaskId)).map((address) =>
  [challengerCandidate, auditor3, auditor4].find(
    (wallet) => wallet.address.toLowerCase() === address.toLowerCase()
  )
);
const challengedDecryptors = (await game.getAssignedDecryptors(challengedTaskId)).map((address) =>
  [decryptor1, decryptor2, decryptor3].find(
    (wallet) => wallet.address.toLowerCase() === address.toLowerCase()
  )
);

const challengedCommitments = [];
const dissentingAuditorAddress = (await game.getAssignedAuditorsForLeaf(
  challengedTaskId,
  badLeafIndex
))[0];
const dissentingAuditor = challengedAuditors.find(
  (wallet) => wallet.address.toLowerCase() === dissentingAuditorAddress.toLowerCase()
);
const challengedErrorDigest = challengeErrorDigest(
  challengedTaskId,
  badLeafIndex,
  badLeaves[badLeafIndex],
  correctLeaves[badLeafIndex]
);
const challengeAuditTraceLeaf = {
  leafIndex: badLeafIndex,
  operatorLeafHash: leafHash(badLeaves[badLeafIndex]),
  recomputedLeafHash: leafHash(correctLeaves[badLeafIndex]),
  errorDigest: challengedErrorDigest
};
const challengeAuditTranscript = buildAuditTranscript({
  taskId: challengedTaskId,
  auditorAddress: dissentingAuditor.address,
  operatorTraceRoot: badTree.root,
  auditTraceLeaf: challengeAuditTraceLeaf,
  operatorLeaf: badLeaves[badLeafIndex],
  recomputedLeaf: correctLeaves[badLeafIndex]
});
for (const auditor of challengedAuditors) {
  const supportsOperator = auditor.address !== dissentingAuditor.address;
  const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
    challengedTaskId,
    auditor.address,
    badLeafIndex
  );
  const podRoot = supportsOperator
    ? ethers.keccak256(
        ethers.toUtf8Bytes(`pod:challenge:${auditor.address}:${supportsOperator}`)
      )
    : challengeAuditTranscript.root;
  challengedCommitments.push(
    await commitAudit(
      game,
      challengedTaskId,
      auditor,
      supportsOperator,
      podRoot,
        auditorCoversChallengedLeaf ? badLeafIndex : undefined,
        badTree.leafCount
    )
  );
}

await provider.send("evm_increaseTime", [21]);
await provider.send("evm_mine", []);
for (let index = 0; index < challengedAuditors.length; index += 1) {
  await openCommittedAudit(
    game,
    challengedTaskId,
    challengedAuditors[index],
    challengedCommitments[index],
    challengedDecryptors.slice(0, 2)
  );
}
await provider.send("evm_increaseTime", [21]);
await provider.send("evm_mine", []);
await (await game.sealDiligenceRandomness(challengedTaskId)).wait();
const diligenceCheckpointIndex = await game.getRequiredDiligenceCheckpointIndex(
  challengedTaskId,
  dissentingAuditor.address
);
const selectedDiligence = selectAuditDiligenceCheckpoint(
  challengeAuditTranscript,
  diligenceCheckpointIndex
);
await (
  await game
    .connect(dissentingAuditor)
    .proveAuditDiligence(
      challengedTaskId,
      selectedDiligence.diligenceCheckpoint,
      selectedDiligence.diligenceProof,
      selectedDiligence.diligenceProofSiblingOnLeft
    )
).wait();
await (
  await game
    .connect(dissentingAuditor)
    .openChallenge(
      challengedTaskId,
      correctTree.root,
      badLeafIndex,
      challengedErrorDigest,
      challengeAuditTraceLeaf,
      challengeAuditTranscript.proof,
      challengeAuditTranscript.proofSiblingOnLeft
    )
).wait();
const challengeClaim = await game.getChallengeClaim(challengedTaskId);

await runDispute(
  game,
  challengedTaskId,
  operator,
  dissentingAuditor,
  badTree,
  correctTree,
  badLeaves[badLeafIndex],
  correctLeaves[badLeafIndex]
);
const challengedTask = await game.getTaskStatus(challengedTaskId);

const output = {
  contractAddress: await game.getAddress(),
  objectiveVerifier: await verifier.getAddress(),
  optimisticTask: {
    taskId: optimisticTaskId,
    decision: Number(optimisticTask.decision),
    finalized: Number(optimisticTask.status) === 3
  },
  challengedTask: {
    taskId: challengedTaskId,
    challenger: dissentingAuditor.address,
    decision: Number(challengedTask.decision),
    finalized: Number(challengedTask.status) === 3,
    operatorRoot: badTree.root,
    challengerRoot: correctTree.root,
    challenge: {
      leafHint: Number(challengeClaim.challengeLeafHint),
      errorDigest: challengeClaim.challengeErrorDigest,
      podRoot: challengeClaim.challengePodRoot
    }
  },
  note:
    "Decision 1 means OperatorAccepted. Decision 2 means OperatorSlashed. The challenged task demonstrates one honest dissenter overturning the operator despite other auditors supporting the operator."
};

await writeJson(path.join(runDir, "evm_demo_result.json"), output);
logStep("protocol demo finished", {
  output: path.join(runDir, "evm_demo_result.json"),
  optimistic_decision: Number(optimisticTask.decision),
  challenged_decision: Number(challengedTask.decision)
});
