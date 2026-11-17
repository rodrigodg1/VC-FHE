// These suites call `authorizeAuthenticatedTask` without a ciphertext manifest,
// so the plan registers clear-value handles (`ciphertextHandleForClear`). That
// is deliberate and sufficient here: what is under test is the binding and
// provenance algebra over opaque 32-byte handles -- input-origin records,
// program/provenance roots, source kinds and the on-chain leaf check -- none of
// which depends on what a handle commits to. Real-FHE regressions separately
// check ciphertext files; neither suite establishes adaptive-release privacy. So
// this file must NOT be run with VCFHE_REQUIRE_FHE_HANDLES=1 (it does not set
// it, and run-poc.sh exports it for the workload stage only).
import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceBlocks,
  advanceTime,
  createProvider,
  HEAVY_WINDOW_SECONDS,
  PAST_HEAVY_WINDOW_SECONDS,
  signerFor
} from "./chain-harness.mjs";
import { ethers } from "ethers";
import { canonicalAuditorFunding } from "../../scripts/canonical-game-driver.mjs";
import { lowerWorkloadSpec } from "../../scripts/application-lowering.mjs";
import {
  authorizeAuthenticatedTask,
  boundCreateTaskArgs,
  buildAuditTranscript,
  buildMerkleTree,
  challengeErrorDigest,
  ciphertextHandleForClear,
  compileContracts,
  getSubtreeChildren,
  leafHash,
  mutateLeafClaim,
  sampleTaskParticipants,
  selectAuditDiligenceCheckpoint,
  terminalOutputBinding,
  traceLeafClaim
} from "../../scripts/evm-lib.mjs";

const mnemonic = "test test test test test test test test test test test junk";

// Bisection and dispute-advance calls carry an explicit gas limit.
//
// Not a workaround for a contract problem: the same calls succeed and the
// dispute advances exactly as asserted below. In `secureTraceMode`,
// `submitBisection` makes a cross-contract staticcall to
// `isDisputeReady`, and ethers' gas estimation binary-searches downward into a
// budget where that inner call runs out of gas. The provider surfaces the
// probe as "missing revert data" (no revert selector, because an out-of-gas
// carries none) instead of continuing the search upward, so estimation fails
// on a transaction that executes fine.
//
// `evm-lib.mjs` already does this for `sampleParticipants`, for the same
// reason. Keeping the estimate out of the way does not weaken the test: every
// assertion about state and revert behaviour is unchanged.
const BISECTION_GAS = { gasLimit: 5_000_000 };

const TERMINAL_WITNESS = {
  lhsInputProof: "0x01", rhsInputProof: "0x01",
  operatorClaimedProof: "0x01", challengerClaimedProof: "0x01"
};

async function reachTerminal(fixture, taskId, challenge) {
  const { game, operator } = fixture;
  let state = await game.getTaskDisputeState(taskId);
  while (Number(state.disputeEnd - state.disputeStart) > 1) {
    const start = Number(state.disputeStart), end = Number(state.disputeEnd);
    const o = getSubtreeChildren(challenge.operatorTree, start, end);
    const c = getSubtreeChildren(challenge.challengerTree, start, end);
    await (await game.connect(operator).submitBisection(taskId, true, o.left, o.right, BISECTION_GAS)).wait();
    await (await game.connect(challenge.challenger).submitBisection(taskId, false, c.left, c.right, BISECTION_GAS)).wait();
    await (await game.advanceDispute(taskId, BISECTION_GAS)).wait();
    state = await game.getTaskDisputeState(taskId);
  }
  return Number(state.disputeStart);
}

async function economicFixture(label, { mutate, errorDigestOverride, diligenceMismatch, singleLeaf, attested } = {}) {
  const fixture = await deployFixture({ attested });
  const taskId = ethers.id(label);
  const operatorLeaves = singleLeaf ? [{ opcode: 1, lhs: 6, rhs: 10, claimed: 60 }] : [
    { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
    { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
    { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
  ];
  const challengedIndex = singleLeaf ? 0 : 2;
  const challengerLeaves = operatorLeaves.map((leaf) => ({ ...leaf }));
  challengerLeaves[challengedIndex].claimed += 1;
  mutate?.(challengerLeaves);
  const diligenceLeaves = challengerLeaves.map((leaf) => ({ ...leaf }));
  if (diligenceMismatch) diligenceLeaves[challengedIndex].claimed += 1;
  const { plan } = await createAuthenticatedTask(fixture, taskId, operatorLeaves, label);
  const challenge = await openAuthenticatedChallenge({
    fixture, taskId, operatorLeaves, challengerLeaves, challengedIndex,
    errorDigestOverride, diligenceLeaves, rejectSameRoot: true
  });
  return { ...fixture, fixture, taskId, plan, challenge, operatorLeaves, challengerLeaves };
}

for (const [fault, options] of [
  ["opcode", { mutate: (leaves) => { leaves[2].opcode = 5; } }],
  ["operands", { mutate: (leaves) => { leaves[2].rhs = 8; } }],
  ["hint", { mutate: (leaves) => { leaves[1].claimed = 16; } }],
  ["digest", { errorDigestOverride: ethers.id("fabricated-error") }],
  ["diligence", { diligenceMismatch: true }]
]) {
  test(`terminal admissibility: committed ${fault} fault loses challenger bond and reopens task`, async () => {
    for (const attested of [false, true]) {
    const f = await economicFixture(`terminal-${fault}-${attested}`, { ...options, attested });
    const { game, operator, availability, taskId, plan, challenge } = f;
    await publishPlan(availability, operator, taskId, plan);
    const index = await reachTerminal(f, taskId, challenge);
    const operatorStake = await game.getParticipantStake(operator.address);
    const challengerStake = await game.getParticipantStake(challenge.challenger.address);
    const leaves = [taskId, traceLeafClaim(f.operatorLeaves[index]), traceLeafClaim(f.challengerLeaves[index])];
    if (attested) {
      // Structural fault evidence needs no KMS signature or decrypted bit.
      await (await game.connect(operator).settleLeafViaAttestedDecision(...leaves, false, true, "0x", BISECTION_GAS)).wait();
    } else {
      await (await game.connect(operator).requestFhevmLeafResolution(...leaves, TERMINAL_WITNESS, BISECTION_GAS)).wait();
    }
    assert.equal(Number((await game.getTaskStatus(taskId))[0]), 1, "task returns to Auditing");
    assert.equal(Number((await game.getTaskStatus(taskId))[1]), 0, "no acceptance verdict");
    assert.equal(await game.getParticipantStake(operator.address), operatorStake + ethers.parseEther("0.5"));
    assert.equal(await game.getParticipantStake(challenge.challenger.address), challengerStake - ethers.parseEther("0.5"));
    assert.equal((await game.getPendingFhevmLeafResolution(taskId)).active, false);
    await expectRevert(() => game.timeoutDispute(taskId));
    const runtime = await f.provider.getCode(await game.getAddress());
    assert.ok((runtime.length - 2) / 2 <= 24_576, "deployed game must fit EIP-170");
    }
  });
}

test("terminal admissibility: unauthenticated caller data cannot slash either participant", async () => {
  const f = await economicFixture("terminal-bad-calldata");
  const { game, operator, availability, taskId, plan, challenge } = f;
  await publishPlan(availability, operator, taskId, plan);
  const index = await reachTerminal(f, taskId, challenge);
  const before = await Promise.all([operator, challenge.challenger].map((s) => game.getParticipantStake(s.address)));
  // A bogus opcode would be attributable only if it matched the committed leaf.
  await expectRevert(() => game.connect(operator).requestFhevmLeafResolution(
    taskId, traceLeafClaim(f.operatorLeaves[index]),
    traceLeafClaim({ ...f.challengerLeaves[index], opcode: 5 }), TERMINAL_WITNESS, BISECTION_GAS
  ));
  assert.deepEqual(await Promise.all([operator, challenge.challenger].map((s) => game.getParticipantStake(s.address))), before);
  assert.equal(Number((await game.getTaskStatus(taskId))[0]), 2);
  await (await game.connect(challenge.challenger).requestFhevmLeafResolution(
    taskId, traceLeafClaim(f.operatorLeaves[index]), traceLeafClaim(f.challengerLeaves[index]),
    TERMINAL_WITNESS, BISECTION_GAS
  )).wait();
  const pending = await game.getPendingFhevmLeafResolution(taskId);
  const bits = await Promise.all([pending.operatorValidHandle, pending.challengerValidHandle].map(async (h) => (await f.fhevm.executor.plaintextOf(h)) !== 0n));
  assert.deepEqual(bits, [true, false]);
  await (await game.finalizeFhevmLeafResolution(taskId, ...bits, "0x01", BISECTION_GAS)).wait();
  assert.equal(Number((await game.getTaskStatus(taskId))[0]), 1);
});

test("terminal admissibility: missing request forfeits challenger bond instead of slashing honest operator", async () => {
  const f = await economicFixture("terminal-withheld-opening", { attested: true });
  const { game, operator, availability, taskId, plan, challenge } = f;
  await publishPlan(availability, operator, taskId, plan);
  const index = await reachTerminal(f, taskId, challenge);
  await expectRevert(() => game.connect(challenge.challenger).settleLeafViaAttestedDecision(
    taskId, traceLeafClaim(f.operatorLeaves[index]), traceLeafClaim(f.challengerLeaves[index]),
    false, true, "0x", BISECTION_GAS
  ));
  assert.equal((await game.getPendingFhevmLeafResolution(taskId)).active, false);
  const stake = await game.getParticipantStake(operator.address);
  await advanceTime(f.provider, PAST_HEAVY_WINDOW_SECONDS);
  await (await game.timeoutDispute(taskId, BISECTION_GAS)).wait();
  assert.equal(Number((await game.getTaskStatus(taskId))[0]), 1);
  assert.equal(await game.getParticipantStake(operator.address), stake + ethers.parseEther("0.5"));
});

test("terminal admissibility: admitted request starts a fresh nonrenewable decision window", async () => {
  const f = await economicFixture("terminal-admitted-timeout");
  const { game, operator, availability, taskId, plan, challenge } = f;
  await publishPlan(availability, operator, taskId, plan);
  const index = await reachTerminal(f, taskId, challenge);
  await advanceTime(f.provider, HEAVY_WINDOW_SECONDS - 2);
  const request = () => game.connect(challenge.challenger).requestFhevmLeafResolution(
    taskId, traceLeafClaim(f.operatorLeaves[index]), traceLeafClaim(f.challengerLeaves[index]),
    TERMINAL_WITNESS, BISECTION_GAS
  );
  await (await request()).wait();
  await advanceTime(f.provider, 3);
  await expectRevert(() => game.timeoutDispute(taskId, BISECTION_GAS));
  await expectRevert(request);
  await advanceTime(f.provider, PAST_HEAVY_WINDOW_SECONDS);
  // A retry after the backend's replacement window cannot extend the deadline.
  await (await request()).wait();
  const stake = await game.getParticipantStake(operator.address);
  await (await game.timeoutDispute(taskId, BISECTION_GAS)).wait();
  assert.equal(Number((await game.getTaskStatus(taskId))[1]), 2);
  assert.equal(await game.getParticipantStake(operator.address), stake - ethers.parseEther("0.5"));
});

test("terminal admissibility: one-leaf disclosure preserves response time and attributes withheld data to operator", async () => {
  const f = await economicFixture("terminal-single-leaf", { singleLeaf: true });
  await advanceTime(f.provider, HEAVY_WINDOW_SECONDS - 1);
  await publishPlan(f.availability, f.operator, f.taskId, f.plan);
  await advanceTime(f.provider, 2);
  await expectRevert(() => f.game.timeoutDispute(f.taskId, BISECTION_GAS));
  await (await f.game.connect(f.challenge.challenger).requestFhevmLeafResolution(
    f.taskId, traceLeafClaim(f.operatorLeaves[0]), traceLeafClaim(f.challengerLeaves[0]),
    TERMINAL_WITNESS, BISECTION_GAS
  )).wait();
  assert.equal((await f.game.getPendingFhevmLeafResolution(f.taskId)).active, true);

  const withheld = await economicFixture("terminal-single-withheld", { singleLeaf: true });
  await advanceTime(withheld.provider, 3 * PAST_HEAVY_WINDOW_SECONDS);
  await expectRevert(() => withheld.game.timeoutDispute(withheld.taskId, BISECTION_GAS));
  await (await withheld.availability.markDisputeTraceUnavailable(withheld.taskId, BISECTION_GAS)).wait();
  assert.equal(Number((await withheld.game.getTaskStatus(withheld.taskId))[1]), 2);
});

async function expectRevert(action) {
  await assert.rejects(async () => {
    const transaction = await action();
    if (transaction?.wait) await transaction.wait();
  }, /CALL_EXCEPTION|transaction execution reverted|revert|reverted|status=0/i);
}

async function deployLocalFhevm(artifacts, deployer) {
  const acl = await new ethers.ContractFactory(
    artifacts.LocalFhevmACL.abi,
    artifacts.LocalFhevmACL.bytecode,
    deployer
  ).deploy();
  await acl.waitForDeployment();
  const executor = await new ethers.ContractFactory(
    artifacts.LocalFhevmExecutor.abi,
    artifacts.LocalFhevmExecutor.bytecode,
    deployer
  ).deploy();
  await executor.waitForDeployment();
  const kms = await new ethers.ContractFactory(
    artifacts.LocalFhevmKMSVerifier.abi,
    artifacts.LocalFhevmKMSVerifier.bytecode,
    deployer
  ).deploy(await acl.getAddress(), await executor.getAddress());
  await kms.waitForDeployment();
  const verifier = await new ethers.ContractFactory(
    artifacts.FhevmObjectiveMicroVerifier.abi,
    artifacts.FhevmObjectiveMicroVerifier.bytecode,
    deployer
  ).deploy(await acl.getAddress(), await executor.getAddress(), await kms.getAddress());
  await verifier.waitForDeployment();
  return { acl, executor, kms, verifier };
}

async function deployFixture({ attested = false, auditorStake = ethers.parseEther("1") } = {}) {
  const provider = await createProvider({ totalAccounts: 12, chainId: 31337 });
  const signers = await Promise.all(Array.from({ length: 10 }, (_, index) => signerFor(provider, index)));
  const [requester, operator, auditor1, auditor2, auditor3, decryptor1, decryptor2, decryptor3] = signers;
  const artifacts = await compileContracts();
  const clearVerifier = await new ethers.ContractFactory(
    artifacts.ObjectiveMicroVerifier.abi,
    artifacts.ObjectiveMicroVerifier.bytecode,
    requester
  ).deploy();
  await clearVerifier.waitForDeployment();
  const game = await new ethers.ContractFactory(
    artifacts.LegacyConfigurableDisputeGame.abi,
    artifacts.LegacyConfigurableDisputeGame.bytecode,
    requester
  ).deploy(await clearVerifier.getAddress(), HEAVY_WINDOW_SECONDS, HEAVY_WINDOW_SECONDS, HEAVY_WINDOW_SECONDS, true);
  await game.waitForDeployment();
  const availability = await new ethers.ContractFactory(
    artifacts.AuthenticatedTraceAvailability.abi,
    artifacts.AuthenticatedTraceAvailability.bytecode,
    requester
  ).deploy(await game.getAddress(), HEAVY_WINDOW_SECONDS);
  await availability.waitForDeployment();
  const fhevm = await deployLocalFhevm(artifacts, requester);
  await (await game.setAvailabilityModule(await availability.getAddress())).wait();
  await (await game.setFhevmVerifier(await fhevm.verifier.getAddress())).wait();
  if (attested) {
    const verifier = await new ethers.ContractFactory(
      artifacts.ZamaKMSVerdictVerifier.abi, artifacts.ZamaKMSVerdictVerifier.bytecode, requester
    ).deploy("VCFHE-Leaf-Decision", "1", 0, ethers.ZeroAddress, [decryptor1.address, decryptor2.address], 2);
    await verifier.waitForDeployment();
    await (await game.setLeafDecisionVerifier(await verifier.getAddress())).wait();
  }

  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  for (const auditor of [auditor1, auditor2, auditor3]) {
    await (await game.connect(auditor).registerAuditor({ value: auditorStake })).wait();
  }
  for (const decryptor of [decryptor1, decryptor2, decryptor3]) {
    await (await game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  }
  return {
    provider,
    requester,
    operator,
    auditors: [auditor1, auditor2, auditor3],
    decryptors: [decryptor1, decryptor2, decryptor3],
    game,
    availability,
    fhevm
  };
}

function signerByAddress(signers, address) {
  return signers.find((signer) => signer.address.toLowerCase() === address.toLowerCase());
}

async function firstAssignedLeaf(game, taskId, auditor, leafCount) {
  for (let index = 0; index < leafCount; index += 1) {
    if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, index)) return index;
  }
  throw new Error("auditor has no assigned leaf");
}

async function openAuthenticatedChallenge({
  fixture,
  taskId,
  operatorLeaves,
  challengerLeaves,
  challengedIndex,
  errorDigestOverride,
  diligenceLeaves = challengerLeaves,
  rejectSameRoot = false,
  beforeOpen
}) {
  const { provider, game, operator, auditors, decryptors } = fixture;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(challengerLeaves);
  const assignedAddresses = await game.getAssignedAuditors(taskId);
  const assignedAuditors = assignedAddresses.map((address) => signerByAddress(auditors, address));
  const challengerAddress = (await game.getAssignedAuditorsForLeaf(taskId, challengedIndex))[0];
  const challenger = signerByAddress(auditors, challengerAddress);
  assert.ok(challenger);

  const errorDigest = errorDigestOverride ?? challengeErrorDigest(
    taskId,
    challengedIndex,
    operatorLeaves[challengedIndex],
    challengerLeaves[challengedIndex]
  );
  const auditTraceLeaf = {
    leafIndex: challengedIndex,
    operatorLeafHash: leafHash(operatorLeaves[challengedIndex]),
    recomputedLeafHash: leafHash(diligenceLeaves[challengedIndex]),
    errorDigest
  };
  const transcript = buildAuditTranscript({
    taskId,
    auditorAddress: challenger.address,
    operatorTraceRoot: operatorTree.root,
    auditTraceLeaf,
    operatorLeaf: operatorLeaves[challengedIndex],
    recomputedLeaf: diligenceLeaves[challengedIndex]
  });

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const isChallenger = auditor.address.toLowerCase() === challenger.address.toLowerCase();
    const podRoot = isChallenger ? transcript.root : ethers.keccak256(
      ethers.toUtf8Bytes(`support:${taskId}:${auditor.address}`)
    );
    const verdict = !isChallenger;
    const salt = ethers.keccak256(ethers.toUtf8Bytes(`salt:${taskId}:${auditor.address}`));
    const verdictCommit = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bool", "bytes32", "bytes32"],
        [verdict, salt, podRoot]
      )
    );
    const auditedLeafIndex = isChallenger
      ? challengedIndex
      : await firstAssignedLeaf(game, taskId, auditor, operatorLeaves.length);
    await (
      await game.connect(auditor).submitAudit(taskId, auditedLeafIndex, podRoot, verdictCommit)
    ).wait();
    auditCommitments.push({ auditor, verdict, salt, podRoot });
  }

  await advanceTime(provider, PAST_HEAVY_WINDOW_SECONDS);
  const assignedDecryptorAddresses = await game.getAssignedDecryptors(taskId);
  const assignedDecryptors = assignedDecryptorAddresses
    .slice(0, 2)
    .map((address) => signerByAddress(decryptors, address));
  for (const commitment of auditCommitments) {
    for (const decryptor of assignedDecryptors) {
      await (
        await game.connect(decryptor).openVerdict(
          taskId,
          commitment.auditor.address,
          commitment.verdict,
          commitment.salt,
          commitment.podRoot
        )
      ).wait();
    }
  }
  await (await game.sealDiligenceRandomness(taskId)).wait();
  const checkpointIndex = await game.getRequiredDiligenceCheckpointIndex(taskId, challenger.address);
  const selected = selectAuditDiligenceCheckpoint(transcript, checkpointIndex);
  await (
    await game.connect(challenger).proveAuditDiligence(
      taskId,
      selected.diligenceCheckpoint,
      selected.diligenceProof,
      selected.diligenceProofSiblingOnLeft
    )
  ).wait();

  await advanceTime(provider, PAST_HEAVY_WINDOW_SECONDS);
  if (rejectSameRoot) {
    const stakeBefore = await game.getParticipantStake(challenger.address);
    await expectRevert(() => game.connect(challenger).openChallenge(
      taskId, operatorTree.root, challengedIndex, errorDigest,
      transcript.leaves[0], transcript.proof, transcript.proofSiblingOnLeft
    ));
    assert.equal(await game.getParticipantStake(challenger.address), stakeBefore);
    assert.equal(Number((await game.getTaskStatus(taskId))[0]), 1);
  }
  await beforeOpen?.({ game, challenger, args: [taskId, challengerTree.root, challengedIndex, errorDigest,
    transcript.leaves[0], transcript.proof, transcript.proofSiblingOnLeft] });
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      challengedIndex,
      errorDigest,
      transcript.leaves[0],
      transcript.proof,
      transcript.proofSiblingOnLeft
    )
  ).wait();
  return { challenger, operatorTree, challengerTree };
}

test("512-leaf challenge funding: one ether is insufficient; deployed-rule funding locks the full bond", async () => {
  // Isolated contract admission regression, not a dataset/FHE/KMS experiment.
  for (const funded of [false, true]) {
    const expectedBond = ethers.parseEther("1.1");
    const f = await deployFixture({ auditorStake: funded ? expectedBond : ethers.parseEther("1") });
    const calculated = canonicalAuditorFunding(512, ...await Promise.all([
      f.game.MIN_AUDITOR_STAKE_WEI(), f.game.DISPUTE_BOND_BASE_WEI(),
      f.game.DISPUTE_BOND_PER_ROUND_WEI(), f.game.SLASH_AMOUNT_WEI()]));
    assert.equal(calculated, expectedBond);
    const taskId = ethers.id(`512-funding-${funded}`);
    const operatorLeaves = Array.from({ length: 512 }, () => ({ opcode: 0, lhs: 1, rhs: 2, claimed: 3,
      lhsRef: { kind: "input", index: 0 }, rhsRef: { kind: "input", index: 1 } }));
    const challengerLeaves = operatorLeaves.map((r, i) => ({ ...r, claimed: i === 511 ? 4 : r.claimed }));
    await createAuthenticatedTask(f, taskId, operatorLeaves, `512-funding-${funded}`);
    const options = { fixture: f, taskId, operatorLeaves, challengerLeaves, challengedIndex: 511 };
    if (!funded) {
      await assert.rejects(openAuthenticatedChallenge({ ...options, beforeOpen: async ({ game, challenger, args }) => {
        assert.equal((await game.getParticipantStakeBreakdown(challenger.address)).availableStakeWei, ethers.parseEther("1"));
        await assert.rejects(game.connect(challenger).openChallenge.staticCall(...args), e => e.data === ethers.id("NotEligible()").slice(0, 10));
        throw new Error("insufficient collateral confirmed before submission");
      }}), /insufficient collateral confirmed/);
      assert.equal(Number((await f.game.getTaskStatus(taskId))[0]), 1);
    } else {
      const { challenger } = await openAuthenticatedChallenge(options);
      const balances = await f.game.getParticipantStakeBreakdown(challenger.address);
      assert.equal(balances.lockedChallengeBondWei, expectedBond);
      assert.equal(balances.availableStakeWei, 0n);
      assert.equal(Number((await f.game.getTaskStatus(taskId))[0]), 2);
    }
  }
});

async function publishPlan(availability, operator, taskId, plan, startIndex = 0) {
  const batch = plan.disclosureLeaves.slice(startIndex);
  await (
    await availability.connect(operator).publishDisputedTraceBatch(
      taskId,
      batch.map((disclosure) => disclosure.leaf),
      batch.map((disclosure) => disclosure.lhsInputProof),
      batch.map((disclosure) => disclosure.rhsInputProof),
      { gasLimit: 4_000_000n }
    )
  ).wait();
}

test("secure trace: authenticated origins, full disputed-trace DA, continuity and handle-based FHEVM finality", async () => {
  const fixture = await deployFixture();
  const { provider, requester, operator, game, availability, fhevm } = fixture;
  const honestLeaves = [
    { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
    { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
    { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
  ];
  const operatorLeaves = honestLeaves.map((leaf) => ({ ...leaf }));
  operatorLeaves[2] = { opcode: 4, lhs: 15, rhs: 7, claimed: 8 };
  operatorLeaves[3] = { opcode: 5, lhs: 8, rhs: 1, claimed: 0 };
  const taskId = ethers.encodeBytes32String("authenticated-trace");
  const operatorTree = buildMerkleTree(operatorLeaves);
  const outputAttestationHash = ethers.id("authenticated-output");
  const binding = terminalOutputBinding(taskId, operatorTree, operatorLeaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: operator.address,
    taskId,
    tree: operatorTree,
    leaves: operatorLeaves,
    resultHash: binding.resultHash,
    outputAttestationHash
  });
  await (
    await game.connect(operator).createTask(
      ...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, outputAttestationHash)
    )
  ).wait();
  await sampleTaskParticipants(game, taskId);
  const challenge = await openAuthenticatedChallenge({
    fixture,
    taskId,
    operatorLeaves,
    challengerLeaves: honestLeaves,
    challengedIndex: 2
  });

  const firstChildren = getSubtreeChildren(operatorTree, 0, operatorTree.leafCount);
  await expectRevert(() =>
    game.connect(operator).submitBisection(taskId, true, firstChildren.left, firstChildren.right)
  );

  const firstDisclosure = plan.disclosureLeaves[0];
  await expectRevert(() =>
    availability.connect(operator).publishDisputedTraceLeaf(
      taskId,
      { ...firstDisclosure.leaf, lhsInputRecord: firstDisclosure.leaf.rhsInputRecord },
      firstDisclosure.lhsInputProof,
      firstDisclosure.rhsInputProof
    )
  );
  await (
    await availability.connect(operator).publishDisputedTraceLeaf(
      taskId,
      firstDisclosure.leaf,
      firstDisclosure.lhsInputProof,
      firstDisclosure.rhsInputProof
    )
  ).wait();

  const secondDisclosure = plan.disclosureLeaves[1];
  await expectRevert(() =>
    availability.connect(operator).publishDisputedTraceLeaf(
      taskId,
      { ...secondDisclosure.leaf, lhsHandle: ciphertextHandleForClear(59) },
      secondDisclosure.lhsInputProof,
      secondDisclosure.rhsInputProof
    )
  );
  await publishPlan(availability, operator, taskId, plan, 1);
  assert.equal(await availability.isDisputeReady(taskId), true);

  let dispute = await game.getTaskDisputeState(taskId);
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const operatorChildren = getSubtreeChildren(challenge.operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challenge.challengerTree, start, end);
    await (
      await game.connect(operator).submitBisection(
        taskId,
        true,
        operatorChildren.left,
        operatorChildren.right,
        BISECTION_GAS
      )
    ).wait();
    await (
      await game.connect(challenge.challenger).submitBisection(
        taskId,
        false,
        challengerChildren.left,
        challengerChildren.right,
        BISECTION_GAS
      )
    ).wait();
    await (await game.advanceDispute(taskId, BISECTION_GAS)).wait();
    dispute = await game.getTaskDisputeState(taskId);
  }
  assert.equal(Number(dispute.disputeStart), 2);
  const disputedSourceLeaf = plan.provenanceLeaves[2];

  await (
    // The terminal round carries opcode + three handles per side and four
    // input proofs. No operand value crosses the ABI.
    await game.connect(challenge.challenger).requestFhevmLeafResolution(
      taskId,
      traceLeafClaim(operatorLeaves[2]),
      traceLeafClaim(honestLeaves[2]),
      {
        lhsInputProof: disputedSourceLeaf.lhsSourceKind === 2 ? "0x" : "0x01",
        rhsInputProof: disputedSourceLeaf.rhsSourceKind === 2 ? "0x" : "0x01",
        operatorClaimedProof: "0x01",
        challengerClaimedProof: "0x01"
      },
      { gasLimit: 2_000_000n }
    )
  ).wait();
  const pending = await game.getPendingFhevmLeafResolution(taskId);
  const operatorValid = (await fhevm.executor.plaintextOf(pending.operatorValidHandle)) !== 0n;
  const challengerValid = (await fhevm.executor.plaintextOf(pending.challengerValidHandle)) !== 0n;
  assert.equal(operatorValid, false);
  assert.equal(challengerValid, true);
  await (
    await game.finalizeFhevmLeafResolution(
      taskId,
      operatorValid,
      challengerValid,
      "0x01"
    )
  ).wait();
  const status = await game.getTaskStatus(taskId);
  assert.equal(Number(status[0]), 3);
  assert.equal(Number(status[1]), 2);

  // Handle substitution: the claimed handles encrypt 60, but the lhs handle
  // encrypts 5 instead of the committed 6, so the homomorphic recomputation
  // yields 50 and BOTH claims are rejected. The check is now purely
  // handle-to-handle, which is exactly why substituting an operand handle can
  // no longer be experimented over by supplying a matching opening.
  const substitutedPair = {
    opcode: 1,
    lhsHandle: ciphertextHandleForClear(5),
    rhsHandle: ciphertextHandleForClear(10),
    operatorClaimedHandle: ciphertextHandleForClear(60),
    challengerClaimedHandle: ciphertextHandleForClear(60),
    lhsSourceKind: 0,
    rhsSourceKind: 0,
    lhsInputProof: "0x01",
    rhsInputProof: "0x01",
    operatorClaimedProof: "0x01",
    challengerClaimedProof: "0x01"
  };
  const substitutedReceipt = await (
    await fhevm.verifier.requestLeafCheck(taskId, 0, substitutedPair, { gasLimit: 1_500_000n })
  ).wait();
  const event = substitutedReceipt.logs
    .map((log) => {
      try { return fhevm.verifier.interface.parseLog(log); } catch { return null; }
    })
    .find((entry) => entry?.name === "FhevmLeafCheckRequested");
  assert.equal(await fhevm.executor.plaintextOf(event.args.operatorValidHandle), 0n);
  assert.equal(await fhevm.executor.plaintextOf(event.args.challengerValidHandle), 0n);

  // A challenged operator that withholds any part of the full trace cannot
  // enter bisection: after the disclosure deadline it is finalized as slashed.
  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  const withholdingTaskId = ethers.encodeBytes32String("withheld-full-trace");
  const withholdingTree = buildMerkleTree(operatorLeaves);
  const withholdingAttestation = ethers.id("withheld-output");
  const withholdingBinding = terminalOutputBinding(
    withholdingTaskId,
    withholdingTree,
    operatorLeaves,
    withholdingAttestation
  );
  await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: operator.address,
    taskId: withholdingTaskId,
    tree: withholdingTree,
    leaves: operatorLeaves,
    resultHash: withholdingBinding.resultHash,
    outputAttestationHash: withholdingAttestation
  });
  await (
    await game.connect(operator).createTask(
      ...boundCreateTaskArgs(
        withholdingTaskId,
        withholdingTree,
        operatorLeaves,
        withholdingAttestation
      )
    )
  ).wait();
  await sampleTaskParticipants(game, withholdingTaskId);
  await openAuthenticatedChallenge({
    fixture,
    taskId: withholdingTaskId,
    operatorLeaves,
    challengerLeaves: honestLeaves,
    challengedIndex: 2
  });
  await advanceTime(provider, PAST_HEAVY_WINDOW_SECONDS);
  await (await availability.markDisputeTraceUnavailable(withholdingTaskId)).wait();
  const withholdingStatus = await game.getTaskStatus(withholdingTaskId);
  assert.equal(Number(withholdingStatus[0]), 3);
  assert.equal(Number(withholdingStatus[1]), 2);
  assert.equal(await availability.isDisputeReady(withholdingTaskId), false);

  await advanceBlocks(provider, 1);
});

// ===========================================================================
// Individual-privacy guard: an individual user's INPUT ciphertext handle must
// never be usable as a verdict commitment, so it can never be decrypted
// through openVerdictViaKMS. (audit: "no process may violate individual
// privacy")
// ===========================================================================
test("individual privacy: a registered input handle cannot be committed as a verdict", async () => {
  const fixture = await deployFixture();
  const { requester, operator, game, availability } = fixture;
  const leaves = [
    { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
    { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
    { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
  ];
  const taskId = ethers.encodeBytes32String("privacy-guard");
  const tree = buildMerkleTree(leaves);
  const outputAttestationHash = ethers.id("privacy-guard-output");
  const binding = terminalOutputBinding(taskId, tree, leaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: operator.address,
    taskId,
    tree,
    leaves,
    resultHash: binding.resultHash,
    outputAttestationHash
  });
  await (
    await game.connect(operator).createTask(
      ...boundCreateTaskArgs(taskId, tree, leaves, outputAttestationHash)
    )
  ).wait();
  await sampleTaskParticipants(game, taskId);

  // An individual user's registered input ciphertext handle.
  const inputHandle = plan.inputRecords[0].ciphertextHandle;
  assert.equal(
    await availability.isRegisteredInputHandle(inputHandle),
    true,
    "the input handle must be registered in the availability module"
  );

  // Find an assigned auditor and its leaf.
  let assigned = null;
  let leafIndex = 0;
  for (const auditor of fixture.auditors) {
    const [isAssigned] = await game.getAuditStatus(taskId, auditor.address);
    if (isAssigned) {
      assigned = auditor;
      leafIndex = await firstAssignedLeaf(game, taskId, auditor, leaves.length);
      break;
    }
  }
  assert.ok(assigned, "expected at least one assigned auditor");
  const podRoot = ethers.id("privacy-guard-pod");

  // The guard: committing the input handle as the verdict must revert.
  await expectRevert(() =>
    game.connect(assigned).submitAudit(taskId, leafIndex, podRoot, inputHandle)
  );

  // Positive control: a genuine (non-input) verdict handle is accepted.
  const verdictHandle = ethers.id("genuine-verdict-ciphertext");
  assert.equal(await availability.isRegisteredInputHandle(verdictHandle), false);
  await (
    await game.connect(assigned).submitAudit(taskId, leafIndex, podRoot, verdictHandle)
  ).wait();
  const [, submitted] = await game.getAuditStatus(taskId, assigned.address);
  assert.equal(submitted, true, "a non-input verdict handle must be accepted");
});

// ===========================================================================
// Pre-challenge disclosure request. Off-chain delivery of the committed trace
// is at the operator's discretion; without an on-chain obligation, an operator
// that delivers the trace to nobody can never be challenged and a faulty task
// finalizes optimistically for free. An assigned auditor may therefore post a
// bonded request during the audit-commit window: the operator must publish the
// complete trace within the disclosure window (the task's deadlines are pushed
// by that window so the auditors can still audit and challenge), or it is
// slashed for withholding and the task closes against it.
// ===========================================================================
async function createAuthenticatedTask(fixture, taskId, operatorLeaves, label) {
  const { requester, operator, game, availability } = fixture;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const outputAttestationHash = ethers.id(label);
  const binding = terminalOutputBinding(taskId, operatorTree, operatorLeaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({
    availability,
    requester,
    operatorAddress: operator.address,
    taskId,
    tree: operatorTree,
    leaves: operatorLeaves,
    resultHash: binding.resultHash,
    outputAttestationHash
  });
  await (
    await game.connect(operator).createTask(
      ...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, outputAttestationHash)
    )
  ).wait();
  await sampleTaskParticipants(game, taskId);
  return { plan, operatorTree };
}

test("explicit compliance DAG: on-chain disclosure binds nonadjacent wires and public constants", async () => {
  const f = await deployFixture();
  const lowered = lowerWorkloadSpec({ id: "explicit-dag", operation: {
    type: "regulatory_compliance_monitor", valuesMilli: [3000, 3000, 3000],
    poorThresholdMilli: 2000, targetPermille: 950
  }});
  const taskId = ethers.id("explicit-dag-disclosure");
  const { plan } = await createAuthenticatedTask(f, taskId, lowered.witnesses, "explicit-output");
  const assigned = await f.game.getAssignedAuditors(taskId);
  const auditor = signerByAddress(f.auditors, assigned[0]);
  await (await f.availability.connect(auditor).requestTraceDisclosure(taskId,
    { value: await f.availability.requiredDisclosureBond(taskId) })).wait();
  const publish = leaves => f.availability.connect(f.operator).publishDisputedTraceBatch(taskId,
    leaves, plan.disclosureLeaves.map(d => d.lhsInputProof),
    plan.disclosureLeaves.map(d => d.rhsInputProof), { gasLimit: 20_000_000 });
  const leaves = plan.disclosureLeaves.map(d => d.leaf);
  assert.equal(leaves[3].lhsSourceIndex, 0);
  assert.equal(leaves[3].rhsSourceIndex, 1);
  // All three comparisons output 1. Replacing wire 0 with wire 2 preserves
  // values and handles in this opaque-handle fixture, but must fail the
  // authorized program root. This was invisible to value-based wire inference.
  const aliased = structuredClone(leaves); aliased[3].lhsSourceIndex = 2;
  await expectRevert(async () => (await publish(aliased)).wait());
  const changedConstant = structuredClone(leaves);
  changedConstant[0].rhsHandle = ciphertextHandleForClear(1999);
  await expectRevert(async () => (await publish(changedConstant)).wait());
  await (await publish(leaves)).wait();
  assert.equal(await f.availability.isDisputeReady(taskId), true);
  assert.equal(await f.availability.isCleared(taskId), true);
});

test("pre-challenge disclosure request: an answered request feeds a normal challenge", async () => {
  const fixture = await deployFixture();
  const { provider, requester, operator, auditors, game, availability, fhevm } = fixture;
  const honestLeaves = [
    { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
    { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
    { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
  ];
  const operatorLeaves = honestLeaves.map((leaf) => ({ ...leaf }));
  operatorLeaves[2] = { opcode: 4, lhs: 15, rhs: 7, claimed: 8 };
  operatorLeaves[3] = { opcode: 5, lhs: 8, rhs: 1, claimed: 0 };

  // ---- (A) request answered by the operator ------------------------------
  const taskId = ethers.encodeBytes32String("pre-challenge-answered");
  const { plan, operatorTree } = await createAuthenticatedTask(fixture, taskId, operatorLeaves, "answered-output");
  const bond = await availability.requiredDisclosureBond(taskId);
  const assigned = (await game.getAssignedAuditors(taskId)).map((address) => signerByAddress(auditors, address));
  const auditor = assigned[0];
  const deadlinesBefore = await game.getTaskDeadlines(taskId);

  // Only an assigned auditor, with exactly the bond.
  await expectRevert(() => availability.connect(requester).requestTraceDisclosure(taskId, { value: bond }));
  await expectRevert(() => availability.connect(auditor).requestTraceDisclosure(taskId, { value: bond - 1n }));
  const requestReceipt = await (
    await availability.connect(auditor).requestTraceDisclosure(taskId, { value: bond })
  ).wait();
  const requested = requestReceipt.logs
    .map((log) => { try { return availability.interface.parseLog(log); } catch { return null; } })
    .find((entry) => entry?.name === "TraceDisclosureRequested");
  assert.ok(requested, "TraceDisclosureRequested must be emitted");
  assert.equal(ethers.getAddress(requested.args.auditor), auditor.address);
  assert.equal(await availability.disclosureRequester(taskId), auditor.address);
  assert.notEqual(Number(await availability.disclosureDeadline(taskId)), 0);
  // Optimistic finalization is blocked while the obligation is open.
  assert.equal(await availability.isCleared(taskId), false);
  // All three audit deadlines moved by the disclosure window.
  const deadlinesAfter = await game.getTaskDeadlines(taskId);
  for (let i = 0; i < 3; i += 1) {
    assert.equal(deadlinesAfter[i] - deadlinesBefore[i], BigInt(HEAVY_WINDOW_SECONDS));
  }
  // One request per task.
  await expectRevert(() => availability.connect(assigned[1]).requestTraceDisclosure(taskId, { value: bond }));

  // The operator publishes the complete trace through the same path a
  // challenge uses; the request bond is credited to it (anti-griefing).
  await publishPlan(availability, operator, taskId, plan, 0);
  assert.equal(await availability.isDisputeReady(taskId), true);
  assert.equal(await availability.isCleared(taskId), true);
  assert.equal(await availability.claimableBond(operator.address), bond);
  assert.equal(await availability.claimableBond(auditor.address), 0n);
  await (await availability.connect(operator).withdrawBond()).wait();
  assert.equal(await availability.claimableBond(operator.address), 0n);

  // The disclosed trace lets the auditor audit, commit, open and challenge
  // within the extended windows; the challenge reuses the completed
  // disclosure and bisection is available at once.
  await advanceTime(provider, HEAVY_WINDOW_SECONDS);
  const challenge = await openAuthenticatedChallenge({
    fixture,
    taskId,
    operatorLeaves,
    challengerLeaves: honestLeaves,
    challengedIndex: 2
  });
  assert.equal(await availability.isDisputeReady(taskId), true);
  let dispute = await game.getTaskDisputeState(taskId);
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const operatorChildren = getSubtreeChildren(challenge.operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challenge.challengerTree, start, end);
    await (await game.connect(operator).submitBisection(taskId, true, operatorChildren.left, operatorChildren.right, BISECTION_GAS)).wait();
    await (await game.connect(challenge.challenger).submitBisection(taskId, false, challengerChildren.left, challengerChildren.right, BISECTION_GAS)).wait();
    await (await game.advanceDispute(taskId, BISECTION_GAS)).wait();
    dispute = await game.getTaskDisputeState(taskId);
  }
  assert.equal(Number(dispute.disputeStart), 2);
  const disputedSourceLeaf = plan.provenanceLeaves[2];
  await (
    await game.connect(challenge.challenger).requestFhevmLeafResolution(
      taskId,
      traceLeafClaim(operatorLeaves[2]),
      traceLeafClaim(honestLeaves[2]),
      {
        lhsInputProof: disputedSourceLeaf.lhsSourceKind === 2 ? "0x" : "0x01",
        rhsInputProof: disputedSourceLeaf.rhsSourceKind === 2 ? "0x" : "0x01",
        operatorClaimedProof: "0x01",
        challengerClaimedProof: "0x01"
      },
      { gasLimit: 2_000_000n }
    )
  ).wait();
  const pending = await game.getPendingFhevmLeafResolution(taskId);
  const operatorValid = (await fhevm.executor.plaintextOf(pending.operatorValidHandle)) !== 0n;
  const challengerValid = (await fhevm.executor.plaintextOf(pending.challengerValidHandle)) !== 0n;
  assert.equal(operatorValid, false);
  assert.equal(challengerValid, true);
  await (await game.finalizeFhevmLeafResolution(taskId, operatorValid, challengerValid, "0x01")).wait();
  const answeredStatus = await game.getTaskStatus(taskId);
  assert.equal(Number(answeredStatus[0]), 3);
  assert.equal(Number(answeredStatus[1]), 2);

  // ---- (C) a request outside the audit-commit window is refused ----------
  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  const lateId = ethers.encodeBytes32String("pre-challenge-late");
  await createAuthenticatedTask(fixture, lateId, operatorLeaves, "late-output");
  const lateAssigned = (await game.getAssignedAuditors(lateId)).map((address) => signerByAddress(auditors, address));
  await advanceTime(provider, PAST_HEAVY_WINDOW_SECONDS);
  await expectRevert(() => availability.connect(lateAssigned[0]).requestTraceDisclosure(lateId, { value: bond }));

  await advanceBlocks(provider, 1);
});

test("pre-challenge trace withholding: an unanswered disclosure request slashes the operator and closes the task", async () => {
  const fixture = await deployFixture();
  const { provider, operator, auditors, game, availability } = fixture;
  const operatorLeaves = [
    { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
    { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { opcode: 4, lhs: 15, rhs: 7, claimed: 8 },
    { opcode: 5, lhs: 8, rhs: 1, claimed: 0 }
  ];
  const withheldId = ethers.encodeBytes32String("pre-challenge-withheld");
  await createAuthenticatedTask(fixture, withheldId, operatorLeaves, "withheld-output");
  const bond = await availability.requiredDisclosureBond(withheldId);
  const withheldAssigned = (await game.getAssignedAuditors(withheldId)).map((address) => signerByAddress(auditors, address));
  const witness = withheldAssigned[0];
  await (await availability.connect(witness).requestTraceDisclosure(withheldId, { value: bond })).wait();
  // Not yet expired: nothing to mark.
  await expectRevert(() => availability.markDisputeTraceUnavailable(withheldId));
  // Past every (extended) deadline, the task still cannot finalize optimistically.
  await advanceTime(provider, 4 * PAST_HEAVY_WINDOW_SECONDS);
  await expectRevert(() => game.finalizeUnchallenged(withheldId));
  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const witnessStakeBefore = await game.getParticipantStake(witness.address);
  await (await availability.markDisputeTraceUnavailable(withheldId, { gasLimit: 1_000_000n })).wait();
  const withheldStatus = await game.getTaskStatus(withheldId);
  assert.equal(Number(withheldStatus[0]), 3, "task must be Finalized");
  assert.equal(Number(withheldStatus[1]), 2, "decision must be OperatorSlashed");
  assert.equal(await game.getParticipantStake(operator.address), operatorStakeBefore - ethers.parseEther("0.5"));
  assert.equal(await game.getParticipantStake(witness.address), witnessStakeBefore + ethers.parseEther("0.5"));
  // The requester's bond is refunded when the operator fails to disclose.
  assert.equal(await availability.claimableBond(witness.address), bond);
  await (await availability.connect(witness).withdrawBond()).wait();
  await expectRevert(() => game.finalizeUnchallenged(withheldId));
  await expectRevert(() => availability.connect(operator).publishDisputedTraceBatch(withheldId, [], [], []));


  await advanceBlocks(provider, 1);
});
