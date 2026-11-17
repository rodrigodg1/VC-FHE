/**
 * Timing-parameter sweep for the non-linear dispute path.
 *
 * The implementation's "Network and timing model" states four things about the
 * deployed contracts. This suite checks each of them against the contracts
 * themselves, under several deployment parameterizations, instead of against
 * the one configuration used by the other suites:
 *
 *   1. Every protocol window is a deployment parameter and is applied exactly:
 *      commit / open / challenge windows in `VerifiableFHEDisputeGame`, the
 *      disclosure window in `AuthenticatedTraceAvailability`. The challenge
 *      window doubles as the per-round bisection deadline.
 *
 *   2. Disclosure rule. A challenged trace of N leaves published in sequential
 *      batches of at most k leaves needs b = ceil(N/k) transactions. With an
 *      inclusion delay of Delta seconds per transaction, an honest operator
 *      completes disclosure iff b * Delta fits inside the disclosure window D.
 *      When it does not, the task ends by withholding slash: operator slashed,
 *      challenger bond released, result never accepted. Publication after the
 *      deadline is rejected; marking the trace unavailable before the deadline
 *      is rejected.
 *
 *   3. Per-round deadlines reset every bisection round (a slow-but-bounded
 *      round sequence completes), and a stalled round ends in default judgment
 *      that never marks the result accepted.
 *
 *   4. Optimistic finalization is impossible up to and including the challenge
 *      deadline and possible right after it when no challenge was opened.
 *
 * Target selection follows chain-harness.mjs: the in-process EVM by default
 * (exact time travel, so the b * Delta <= D boundary is checked exactly), or a
 * real chain via VCFHE_TEST_RPC_URL, where Delta is waited out in wall-clock
 * time and every transaction also costs a block. On a real chain the suite
 * therefore asserts the invariant the contract actually enforces (a batch is
 * accepted iff its block timestamp <= the on-chain disclosure deadline) rather
 * than the exact arithmetic.
 *
 * Run:  npm run test:timing
 *       VCFHE_TIMING_MATRIX=experiment npm run test:timing   (evaluation configuration only)
 */
import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  advanceTime,
  advanceToTimestamp,
  chainTimestamp,
  createProvider,
  onExternalChain,
  signerFor
} from "./chain-harness.mjs";
import {
  authorizeAuthenticatedTask,
  boundCreateTaskArgs,
  buildAuditTranscript,
  buildMerkleTree,
  challengeErrorDigest,
  compileContracts,
  getSubtreeChildren,
  leafHash,
  sampleTaskParticipants,
  selectAuditDiligenceCheckpoint,
  terminalOutputBinding,
  traceLeafClaim
} from "../../scripts/evm-lib.mjs";

// ---------------------------------------------------------------------------
// Parameter matrix
// ---------------------------------------------------------------------------
//
//   W      commit = open = challenge window (seconds); also the per-round
//          bisection deadline
//   D      disclosure window (seconds), the separate availability parameter
//   N      trace length (leaves, power of two)
//   k      leaves per disclosure transaction (chosen by the publisher)
//   delta  simulated inclusion delay before every disclosure transaction
//   round  simulated delay before every bisection round (must stay < W)
//
// The expected outcome is NOT hard-coded: it is derived from the timing
// model's own rule, b = ceil(N/k), complete iff b * delta <= D, and the suite
// then checks that the contracts agree with that rule.
const OPCODE_ADD = 6;
const SLASH_WEI = ethers.parseEther("0.5");
const BISECTION_GAS = { gasLimit: 5_000_000 };

const FULL_MATRIX = [
  // Adequate windows: disclosure fits, bisection rounds each stay inside W.
  { label: "N=4  k=2  delta=5  D=20  (b=2 -> 10s <= 20s)",  W: 20, D: 20,  N: 4,  k: 2,  delta: 5,  round: 18 },
  { label: "N=8  k=2  delta=4  D=20  (b=4 -> 16s <= 20s)",  W: 20, D: 20,  N: 8,  k: 2,  delta: 4,  round: 18 },
  { label: "N=16 k=4  delta=4  D=20  (b=4 -> 16s <= 20s)",  W: 20, D: 20,  N: 16, k: 4,  delta: 4,  round: 18 },
  { label: "N=16 k=16 delta=15 D=20  (b=1 -> 15s <= 20s)",  W: 20, D: 20,  N: 16, k: 16, delta: 15, round: 18 },
  // Boundary: b * delta == D exactly. The contract accepts a batch while
  // block.timestamp <= deadline, so the boundary itself completes; the experiment's
  // "must exceed b*Delta plus a finality margin" is the safe provisioning rule.
  { label: "N=8  k=2  delta=5  D=20  (b=4 -> 20s == 20s, boundary)", W: 20, D: 20, N: 8, k: 2, delta: 5, round: 18 },
  // Inadequate disclosure window: withholding-slash path must engage, never acceptance.
  { label: "N=8  k=2  delta=8  D=20  (b=4 -> 32s > 20s)",   W: 20, D: 20,  N: 8,  k: 2,  delta: 8,  round: 18 },
  { label: "N=16 k=2  delta=5  D=20  (b=8 -> 40s > 20s)",   W: 20, D: 20,  N: 16, k: 2,  delta: 5,  round: 18 },
  { label: "N=16 k=16 delta=21 D=20  (b=1 -> 21s > 20s)",   W: 20, D: 20,  N: 16, k: 16, delta: 21, round: 18 },
  // Evaluation configuration (Section "Blockchain platform and network configuration"):
  // 40 s commit/open/challenge windows, 300 s disclosure window, 8 leaves per batch,
  // about 8 s submit-to-receipt on the QBFT network.
  { label: "experiment: W=40 D=300 N=16 k=8 delta=8 (b=2 -> 16s <= 300s)", W: 40, D: 300, N: 16, k: 8, delta: 8, round: 30 }
];

const EXPERIMENT_MATRIX = FULL_MATRIX.filter((row) => row.label.startsWith("experiment"));

const MATRIX = (() => {
  const selection = process.env.VCFHE_TIMING_MATRIX || "full";
  if (selection === "experiment") return EXPERIMENT_MATRIX;
  if (selection === "full") return FULL_MATRIX;
  try {
    const custom = JSON.parse(selection);
    if (Array.isArray(custom) && custom.length > 0) return custom;
  } catch {
    // fall through
  }
  throw new Error(`VCFHE_TIMING_MATRIX must be "full", "experiment", or a JSON array of rows`);
})();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function expectRevert(action, message) {
  await assert.rejects(async () => {
    const transaction = await action();
    if (transaction?.wait) await transaction.wait();
  }, /CALL_EXCEPTION|transaction execution reverted|revert|reverted|status=0|missing revert data/i, message);
}

async function deployLocalFhevm(artifacts, deployer) {
  const acl = await new ethers.ContractFactory(
    artifacts.LocalFhevmACL.abi, artifacts.LocalFhevmACL.bytecode, deployer
  ).deploy();
  await acl.waitForDeployment();
  const executor = await new ethers.ContractFactory(
    artifacts.LocalFhevmExecutor.abi, artifacts.LocalFhevmExecutor.bytecode, deployer
  ).deploy();
  await executor.waitForDeployment();
  const kms = await new ethers.ContractFactory(
    artifacts.LocalFhevmKMSVerifier.abi, artifacts.LocalFhevmKMSVerifier.bytecode, deployer
  ).deploy(await acl.getAddress(), await executor.getAddress());
  await kms.waitForDeployment();
  const verifier = await new ethers.ContractFactory(
    artifacts.FhevmObjectiveMicroVerifier.abi, artifacts.FhevmObjectiveMicroVerifier.bytecode, deployer
  ).deploy(await acl.getAddress(), await executor.getAddress(), await kms.getAddress());
  await verifier.waitForDeployment();
  return { acl, executor, kms, verifier };
}

/**
 * Deploys the full secure-mode stack with explicit window parameters.
 * `commit`, `open`, `challenge` and `disclosure` are seconds.
 */
async function deployFixture({ commit, open, challenge, disclosure }) {
  const provider = await createProvider({ totalAccounts: 12, chainId: 31337 });
  const signers = await Promise.all(Array.from({ length: 10 }, (_, i) => signerFor(provider, i)));
  const [requester, operator, auditor1, auditor2, auditor3, decryptor1, decryptor2, decryptor3] = signers;
  const artifacts = await compileContracts();

  const clearVerifier = await new ethers.ContractFactory(
    artifacts.ObjectiveMicroVerifier.abi, artifacts.ObjectiveMicroVerifier.bytecode, requester
  ).deploy();
  await clearVerifier.waitForDeployment();

  const game = await new ethers.ContractFactory(
    artifacts.LegacyConfigurableDisputeGame.abi, artifacts.LegacyConfigurableDisputeGame.bytecode, requester
  ).deploy(await clearVerifier.getAddress(), commit, open, challenge, true);
  await game.waitForDeployment();

  const availability = await new ethers.ContractFactory(
    artifacts.AuthenticatedTraceAvailability.abi, artifacts.AuthenticatedTraceAvailability.bytecode, requester
  ).deploy(await game.getAddress(), disclosure);
  await availability.waitForDeployment();

  const fhevm = await deployLocalFhevm(artifacts, requester);
  await (await game.setAvailabilityModule(await availability.getAddress())).wait();
  await (await game.setFhevmVerifier(await fhevm.verifier.getAddress())).wait();

  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  for (const auditor of [auditor1, auditor2, auditor3]) {
    await (await game.connect(auditor).registerAuditor({ value: ethers.parseEther("1") })).wait();
  }
  for (const decryptor of [decryptor1, decryptor2, decryptor3]) {
    await (await game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  }
  return {
    provider, requester, operator,
    auditors: [auditor1, auditor2, auditor3],
    decryptors: [decryptor1, decryptor2, decryptor3],
    game, availability, fhevm,
    windows: { commit, open, challenge, disclosure }
  };
}

/**
 * An N-leaf ADD chain: leaf i computes claimed_i = lhs_i + rhs_i with
 * lhs_i = claimed_{i-1} (previous output) and a constant rhs. The operator's
 * trace equals the honest one up to `corruptIndex`, where it reports
 * honest + 1, and then keeps computing honestly from its own wrong value,
 * so each trace is internally consistent and the two diverge from
 * `corruptIndex` onward. rhs is chosen so that it never equals a previous
 * output (which the plan builder would read as a dataflow edge).
 */
function buildChains(leafCount, corruptIndex) {
  const RHS = 3;
  const honest = [];
  const operator = [];
  let honestPrev = 10;
  let operatorPrev = 10;
  for (let i = 0; i < leafCount; i += 1) {
    const honestLhs = i === 0 ? 10 : honestPrev;
    const operatorLhs = i === 0 ? 10 : operatorPrev;
    const honestClaimed = honestLhs + RHS;
    let operatorClaimed = operatorLhs + RHS;
    if (i === corruptIndex) operatorClaimed += 1;
    honest.push({ opcode: OPCODE_ADD, lhs: honestLhs, rhs: RHS, claimed: honestClaimed });
    operator.push({ opcode: OPCODE_ADD, lhs: operatorLhs, rhs: RHS, claimed: operatorClaimed });
    honestPrev = honestClaimed;
    operatorPrev = operatorClaimed;
  }
  return { honest, operator };
}

function signerByAddress(signers, address) {
  return signers.find((s) => s.address.toLowerCase() === address.toLowerCase());
}

async function firstAssignedLeaf(game, taskId, auditor, leafCount) {
  for (let index = 0; index < leafCount; index += 1) {
    if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, index)) return index;
  }
  throw new Error("auditor has no assigned leaf");
}

/** Authorizes, creates and samples a task for `operatorLeaves`. */
async function createAuthorizedTask(fixture, { taskId, operatorLeaves }) {
  const { requester, operator, game, availability } = fixture;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const outputAttestationHash = ethers.id(`output:${taskId}`);
  const binding = terminalOutputBinding(taskId, operatorTree, operatorLeaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({
    availability, requester,
    operatorAddress: operator.address,
    taskId, tree: operatorTree, leaves: operatorLeaves,
    resultHash: binding.resultHash, outputAttestationHash
  });
  await (
    await game.connect(operator).createTask(
      ...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, outputAttestationHash)
    )
  ).wait();
  await sampleTaskParticipants(game, taskId);
  return { plan, operatorTree };
}

/**
 * Drives a sampled task through audit commit -> verdict opening -> diligence
 * proof -> openChallenge, using the fixture's own windows to cross phases.
 * Returns the challenger and both trees.
 */
async function openChallenge(fixture, { taskId, operatorLeaves, honestLeaves, challengedIndex }) {
  const { provider, game, auditors, decryptors, windows } = fixture;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(honestLeaves);
  const assignedAuditors = (await game.getAssignedAuditors(taskId)).map((a) => signerByAddress(auditors, a));
  const challengerAddress = (await game.getAssignedAuditorsForLeaf(taskId, challengedIndex))[0];
  const challenger = signerByAddress(auditors, challengerAddress);
  assert.ok(challenger, "a stage auditor must be assigned to the challenged leaf");

  const errorDigest = challengeErrorDigest(
    taskId, challengedIndex, operatorLeaves[challengedIndex], honestLeaves[challengedIndex]
  );
  const auditTraceLeaf = {
    leafIndex: challengedIndex,
    operatorLeafHash: leafHash(operatorLeaves[challengedIndex]),
    recomputedLeafHash: leafHash(honestLeaves[challengedIndex]),
    errorDigest
  };
  const transcript = buildAuditTranscript({
    taskId, auditorAddress: challenger.address,
    operatorTraceRoot: operatorTree.root, auditTraceLeaf,
    operatorLeaf: operatorLeaves[challengedIndex], recomputedLeaf: honestLeaves[challengedIndex]
  });

  // Commit window.
  const commitments = [];
  for (const auditor of assignedAuditors) {
    const isChallenger = auditor.address.toLowerCase() === challenger.address.toLowerCase();
    const podRoot = isChallenger
      ? transcript.root
      : ethers.keccak256(ethers.toUtf8Bytes(`support:${taskId}:${auditor.address}`));
    const verdict = !isChallenger;
    const salt = ethers.keccak256(ethers.toUtf8Bytes(`salt:${taskId}:${auditor.address}`));
    const verdictCommit = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["bool", "bytes32", "bytes32"], [verdict, salt, podRoot])
    );
    const auditedLeafIndex = isChallenger
      ? challengedIndex
      : await firstAssignedLeaf(game, taskId, auditor, operatorLeaves.length);
    await (await game.connect(auditor).submitAudit(taskId, auditedLeafIndex, podRoot, verdictCommit)).wait();
    commitments.push({ auditor, verdict, salt, podRoot });
  }

  // Open window: cross the commit deadline using the on-chain deadline itself.
  const [commitDeadline, openDeadline] = await game.getTaskDeadlines(taskId);
  await advanceToTimestamp(provider, Number(commitDeadline) + 1);
  const assignedDecryptors = (await game.getAssignedDecryptors(taskId))
    .slice(0, 2).map((a) => signerByAddress(decryptors, a));
  for (const c of commitments) {
    for (const decryptor of assignedDecryptors) {
      await (await game.connect(decryptor).openVerdict(taskId, c.auditor.address, c.verdict, c.salt, c.podRoot)).wait();
    }
  }
  await (await game.sealDiligenceRandomness(taskId)).wait();
  const checkpointIndex = await game.getRequiredDiligenceCheckpointIndex(taskId, challenger.address);
  const selected = selectAuditDiligenceCheckpoint(transcript, checkpointIndex);
  await (
    await game.connect(challenger).proveAuditDiligence(
      taskId, selected.diligenceCheckpoint, selected.diligenceProof, selected.diligenceProofSiblingOnLeft
    )
  ).wait();

  // Challenge window.
  await advanceToTimestamp(provider, Number(openDeadline) + 1);
  const receipt = await (
    await game.connect(challenger).openChallenge(
      taskId, challengerTree.root, challengedIndex, errorDigest,
      transcript.leaves[0], transcript.proof, transcript.proofSiblingOnLeft
    )
  ).wait();
  const openedAt = (await provider.getBlock(receipt.blockNumber)).timestamp;
  void windows;
  return { challenger, operatorTree, challengerTree, openedAt };
}

/**
 * Publishes the disclosure in batches of `k` leaves, advancing the clock by
 * `delta` before every transaction. Stops at the first rejected batch.
 * Returns what happened, with the block timestamps the contract saw.
 */
async function publishInBatches(fixture, { taskId, plan, k, delta }) {
  const { provider, availability, operator } = fixture;
  const deadline = Number(await availability.disclosureDeadline(taskId));
  const leaves = plan.disclosureLeaves;
  const b = Math.ceil(leaves.length / k);
  const batches = [];
  for (let start = 0; start < leaves.length; start += k) {
    if (delta > 0) await advanceTime(provider, delta);
    const batch = leaves.slice(start, start + k);
    const nowBefore = await chainTimestamp(provider);
    try {
      const receipt = await (
        await availability.connect(operator).publishDisputedTraceBatch(
          taskId,
          batch.map((d) => d.leaf),
          batch.map((d) => d.lhsInputProof),
          batch.map((d) => d.rhsInputProof),
          { gasLimit: 6_000_000n }
        )
      ).wait();
      const at = (await provider.getBlock(receipt.blockNumber)).timestamp;
      batches.push({ index: batches.length, accepted: true, at });
      // The contract's own rule: accepted only while block.timestamp <= deadline.
      assert.ok(at <= deadline, `batch ${batches.length} accepted at ${at} after deadline ${deadline}`);
    } catch (error) {
      const at = await chainTimestamp(provider);
      batches.push({ index: batches.length, accepted: false, at, error: String(error.message || error).slice(0, 80) });
      assert.ok(
        at > deadline,
        `batch ${batches.length} rejected at ${at} although deadline ${deadline} had not passed (nowBefore=${nowBefore})`
      );
      break;
    }
  }
  const completed = batches.length === b && batches.every((x) => x.accepted);
  return { b, deadline, batches, completed };
}

/** Runs bisection to the leaf, advancing `roundDelay` before each round. */
async function bisectToLeaf(fixture, { taskId, challenger, operatorTree, challengerTree, roundDelay }) {
  const { provider, game, operator } = fixture;
  let dispute = await game.getTaskDisputeState(taskId);
  let rounds = 0;
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    if (roundDelay > 0) await advanceTime(provider, roundDelay);
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const o = getSubtreeChildren(operatorTree, start, end);
    const c = getSubtreeChildren(challengerTree, start, end);
    await (await game.connect(operator).submitBisection(taskId, true, o.left, o.right, BISECTION_GAS)).wait();
    await (await game.connect(challenger).submitBisection(taskId, false, c.left, c.right, BISECTION_GAS)).wait();
    // A complete round cannot be timed out; it must be advanced.
    await expectRevert(() => game.timeoutDispute(taskId, { gasLimit: 1_000_000 }),
      "a round with both branches posted must not be timed out");
    await (await game.advanceDispute(taskId, BISECTION_GAS)).wait();
    dispute = await game.getTaskDisputeState(taskId);
    rounds += 1;
  }
  return { rounds, leafIndex: Number(dispute.disputeStart) };
}

/** Terminal round through the (local) FHEVM verifier; returns the decision. */
async function resolveTerminalLeaf(fixture, { taskId, challenger, plan, operatorLeaves, honestLeaves, leafIndex }) {
  const { game, fhevm } = fixture;
  const source = plan.provenanceLeaves[leafIndex];
  await (
    await game.connect(challenger).requestFhevmLeafResolution(
      taskId,
      traceLeafClaim(operatorLeaves[leafIndex]),
      traceLeafClaim(honestLeaves[leafIndex]),
      {
        lhsInputProof: source.lhsSourceKind === 2 ? "0x" : "0x01",
        rhsInputProof: source.rhsSourceKind === 2 ? "0x" : "0x01",
        operatorClaimedProof: "0x01",
        challengerClaimedProof: "0x01"
      },
      { gasLimit: 2_000_000n }
    )
  ).wait();
  const pending = await game.getPendingFhevmLeafResolution(taskId);
  const operatorValid = (await fhevm.executor.plaintextOf(pending.operatorValidHandle)) !== 0n;
  const challengerValid = (await fhevm.executor.plaintextOf(pending.challengerValidHandle)) !== 0n;
  await (await game.finalizeFhevmLeafResolution(taskId, operatorValid, challengerValid, "0x01")).wait();
  const status = await game.getTaskStatus(taskId);
  return { operatorValid, challengerValid, status: Number(status[0]), decision: Number(status[1]) };
}

function fmt(row) {
  return `W=${row.W}s D=${row.D}s N=${row.N} k=${row.k} delta=${row.delta}s round=${row.round}s`;
}

// ---------------------------------------------------------------------------
// 1. Deployment parameters are applied exactly
// ---------------------------------------------------------------------------
test("timing: every window is a deployment parameter and shapes the on-chain deadlines", async () => {
  const windows = { commit: 17, open: 23, challenge: 31, disclosure: 127 };
  const fixture = await deployFixture(windows);
  const { game, availability, provider } = fixture;

  assert.equal(Number(await game.COMMIT_WINDOW_SECONDS()), windows.commit);
  assert.equal(Number(await game.OPEN_WINDOW_SECONDS()), windows.open);
  assert.equal(Number(await game.CHALLENGE_WINDOW_SECONDS()), windows.challenge);
  assert.equal(Number(await availability.disclosureWindowSeconds()), windows.disclosure);

  const { honest, operator } = buildChains(4, 2);
  const taskId = ethers.encodeBytes32String("timing-params");
  await createAuthorizedTask(fixture, { taskId, operatorLeaves: operator });
  const [commitDeadline, openDeadline, challengeDeadline] = await game.getTaskDeadlines(taskId);
  const now = await chainTimestamp(provider);
  // Windows start at sampling and chain: commit, then open, then challenge.
  assert.ok(Number(commitDeadline) >= now, "commit window must be live right after sampling");
  assert.equal(Number(openDeadline) - Number(commitDeadline), windows.open);
  assert.equal(Number(challengeDeadline) - Number(openDeadline), windows.challenge);

  // The disclosure window is measured from the moment the challenge opens.
  const { openedAt } = await openChallenge(fixture, {
    taskId, operatorLeaves: operator, honestLeaves: honest, challengedIndex: 2
  });
  assert.equal(Number(await availability.disclosureDeadline(taskId)), openedAt + windows.disclosure);

  // Bisection cannot start before the full trace is disclosed.
  const tree = buildMerkleTree(operator);
  const children = getSubtreeChildren(tree, 0, tree.leafCount);
  await expectRevert(
    () => game.connect(fixture.operator).submitBisection(taskId, true, children.left, children.right, BISECTION_GAS),
    "bisection must be blocked until disclosure is complete"
  );
  // Zero windows are rejected at deployment.
  const artifacts = await compileContracts();
  await assert.rejects(
    new ethers.ContractFactory(
      artifacts.AuthenticatedTraceAvailability.abi, artifacts.AuthenticatedTraceAvailability.bytecode, fixture.requester
    ).deploy(await game.getAddress(), 0)
  );
});

// ---------------------------------------------------------------------------
// 2 + 3. Disclosure rule and per-round deadlines, over the parameter matrix
// ---------------------------------------------------------------------------
for (const row of MATRIX) {
  const b = Math.ceil(row.N / row.k);
  const needed = b * row.delta;
  const expectedComplete = needed <= row.D;

  test(`timing sweep [${row.label}] ${fmt(row)} -> b=${b}, b*delta=${needed}s, expect ${expectedComplete ? "complete" : "withholding slash"}`, async () => {
    assert.ok(row.round < row.W, "matrix rows must keep the per-round delay inside the challenge window");
    const fixture = await deployFixture({ commit: row.W, open: row.W, challenge: row.W, disclosure: row.D });
    const { game, availability, operator, provider } = fixture;
    const challengedIndex = Math.floor(row.N / 2); // a leaf the bisection has to find
    const { honest, operator: operatorLeaves } = buildChains(row.N, challengedIndex);
    const taskId = ethers.id(`timing:${row.label}`);
    const { plan } = await createAuthorizedTask(fixture, { taskId, operatorLeaves });
    const { challenger, operatorTree, challengerTree } = await openChallenge(fixture, {
      taskId, operatorLeaves, honestLeaves: honest, challengedIndex
    });

    const operatorStakeBefore = await game.getParticipantStake(operator.address);
    const challengerStakeBefore = await game.getParticipantStake(challenger.address);
    const bondLocked = (await game.getParticipantStakeBreakdown(challenger.address))[1];
    assert.ok(bondLocked > 0n, "the challenger bond must be locked while the dispute is open");

    // Marking the trace unavailable before the deadline is rejected.
    await expectRevert(() => availability.markDisputeTraceUnavailable(taskId),
      "unavailability cannot be declared before the disclosure deadline");

    const disclosure = await publishInBatches(fixture, { taskId, plan, k: row.k, delta: row.delta });
    assert.equal(disclosure.b, b);
    if (!onExternalChain) {
      // Exact clock: the contracts must agree with the timing model's rule.
      assert.equal(disclosure.completed, expectedComplete,
        `b*delta=${needed}s vs D=${row.D}s: expected ${expectedComplete ? "completion" : "failure"}, got ${JSON.stringify(disclosure.batches)}`);
    }

    if (disclosure.completed) {
      assert.equal(await availability.isDisputeReady(taskId), true);
      // Publishing past completion is rejected (state, not time).
      await expectRevert(() => availability.markDisputeTraceUnavailable(taskId),
        "a fully disclosed trace cannot be marked unavailable");

      // Slow but bounded rounds: each round gets a fresh deadline.
      const { rounds, leafIndex } = await bisectToLeaf(fixture, {
        taskId, challenger, operatorTree, challengerTree, roundDelay: row.round
      });
      assert.equal(rounds, Math.log2(row.N));
      assert.equal(leafIndex, challengedIndex, "bisection must isolate the corrupted leaf");

      const outcome = await resolveTerminalLeaf(fixture, {
        taskId, challenger, plan, operatorLeaves, honestLeaves: honest, leafIndex
      });
      assert.equal(outcome.operatorValid, false, "the operator's corrupted leaf must fail re-execution");
      assert.equal(outcome.challengerValid, true, "the honest leaf must pass re-execution");
      assert.equal(outcome.status, 3, "task must be finalized");
      assert.equal(outcome.decision, 2, "decision must be OperatorSlashed after objective resolution");
    } else {
      // Withholding path: the first late batch was rejected; the operator cannot
      // resume, the challenger (or anyone) can declare unavailability, and the
      // task ends slashed, bond released, never accepted.
      assert.equal(await availability.isDisputeReady(taskId), false);
      await expectRevert(
        () => {
          const next = plan.disclosureLeaves.slice(disclosure.batches.filter((x) => x.accepted).length * row.k)[0];
          return availability.connect(operator).publishDisputedTraceLeaf(
            taskId, next.leaf, next.lhsInputProof, next.rhsInputProof, { gasLimit: 2_000_000n }
          );
        },
        "no publication is accepted after the disclosure deadline"
      );
      await (await availability.markDisputeTraceUnavailable(taskId, { gasLimit: 1_000_000n })).wait();
      const status = await game.getTaskStatus(taskId);
      assert.equal(Number(status[0]), 3, "task must be finalized");
      assert.equal(Number(status[1]), 2, "decision must be OperatorSlashed (withholding)");
      assert.notEqual(Number(status[1]), 1, "a withheld trace must never be accepted");
      assert.equal(
        await game.getParticipantStake(operator.address), operatorStakeBefore - SLASH_WEI,
        "operator loses the slash amount"
      );
      assert.equal(
        await game.getParticipantStake(challenger.address), challengerStakeBefore + SLASH_WEI,
        "challenger receives the slash"
      );
      assert.equal(
        (await game.getParticipantStakeBreakdown(challenger.address))[1], 0n,
        "the challenger bond must be released, not locked forever"
      );
      // Nothing else can move the task.
      await expectRevert(() => availability.markDisputeTraceUnavailable(taskId, { gasLimit: 1_000_000n }));
      await expectRevert(() => game.timeoutDispute(taskId, { gasLimit: 1_000_000 }));
    }
    void provider;
  });
}

// ---------------------------------------------------------------------------
// 3. Stalled rounds: default judgment, terminal round included, never acceptance
// ---------------------------------------------------------------------------
test("timing: a stalled bisection round ends by default judgment after exactly the round window", async () => {
  const W = 20;
  const fixture = await deployFixture({ commit: W, open: W, challenge: W, disclosure: 60 });
  const { game, operator, provider } = fixture;
  const { honest, operator: operatorLeaves } = buildChains(8, 5);
  const taskId = ethers.id("timing:stall-operator");
  const { plan } = await createAuthorizedTask(fixture, { taskId, operatorLeaves });
  const { challenger, challengerTree } = await openChallenge(fixture, {
    taskId, operatorLeaves, honestLeaves: honest, challengedIndex: 5
  });
  const disclosure = await publishInBatches(fixture, { taskId, plan, k: 8, delta: 0 });
  assert.equal(disclosure.completed, true);

  // Challenger posts, operator stays silent.
  const dispute = await game.getTaskDisputeState(taskId);
  const c = getSubtreeChildren(challengerTree, Number(dispute.disputeStart), Number(dispute.disputeEnd));
  await (await game.connect(challenger).submitBisection(taskId, false, c.left, c.right, BISECTION_GAS)).wait();

  const operatorBefore = await game.getParticipantStake(operator.address);
  const challengerBefore = await game.getParticipantStake(challenger.address);
  await expectRevert(() => game.timeoutDispute(taskId, { gasLimit: 1_000_000 }),
    "timeout must be rejected before the round deadline");
  await advanceTime(provider, W + 60 + 1);
  await (await game.timeoutDispute(taskId, { gasLimit: 1_000_000 })).wait();
  const status = await game.getTaskStatus(taskId);
  assert.equal(Number(status[0]), 3);
  assert.equal(Number(status[1]), 2, "silent operator is slashed by default judgment");
  assert.equal(await game.getParticipantStake(operator.address), operatorBefore - SLASH_WEI);
  assert.equal(await game.getParticipantStake(challenger.address), challengerBefore + SLASH_WEI);
});

test("timing: a challenger that abandons its challenge forfeits the bond; the result is still not accepted", async () => {
  const W = 20;
  const fixture = await deployFixture({ commit: W, open: W, challenge: W, disclosure: 60 });
  const { game, provider } = fixture;
  const { honest, operator: operatorLeaves } = buildChains(8, 5);
  const taskId = ethers.id("timing:stall-challenger");
  const { plan } = await createAuthorizedTask(fixture, { taskId, operatorLeaves });
  await openChallenge(fixture, { taskId, operatorLeaves, honestLeaves: honest, challengedIndex: 5 });
  const disclosure = await publishInBatches(fixture, { taskId, plan, k: 4, delta: 0 });
  assert.equal(disclosure.completed, true);

  await advanceTime(provider, W + 60 + 1);
  await (await game.timeoutDispute(taskId, { gasLimit: 1_000_000 })).wait();
  const status = await game.getTaskStatus(taskId);
  assert.equal(Number(status[0]), 1, "a lost challenge reopens the task");
  assert.equal(Number(status[1]), 0, "abandonment is not an acceptance verdict");
});

// ---------------------------------------------------------------------------
// 4. Optimistic finalization is gated exactly by the challenge deadline
// ---------------------------------------------------------------------------
test("timing: optimistic finalization is rejected through the challenge deadline and accepted right after", async () => {
  const fixture = await deployFixture({ commit: 11, open: 13, challenge: 29, disclosure: 60 });
  const { game, provider } = fixture;
  const { operator: operatorLeaves } = buildChains(4, 1);
  const taskId = ethers.id("timing:optimistic");
  await createAuthorizedTask(fixture, { taskId, operatorLeaves });
  const [, , challengeDeadline] = await game.getTaskDeadlines(taskId);

  // Explicit gas limit, as the other suites do for cross-contract calls in
  // secure mode: `finalizeUnchallenged` staticcalls the availability module's
  // `isCleared`, and the in-process EVM's gas estimation probes budgets in
  // which that inner call runs out of gas and reports "missing revert data"
  // for a transaction that executes fine. The assertions below are unchanged.
  const FINALIZE_GAS = { gasLimit: 1_000_000 };
  await expectRevert(() => game.finalizeUnchallenged(taskId, FINALIZE_GAS),
    "finalization before the window closes is rejected");
  await advanceToTimestamp(provider, Number(challengeDeadline)); // == deadline: still inside
  if (!onExternalChain) {
    await expectRevert(() => game.finalizeUnchallenged(taskId, FINALIZE_GAS),
      "finalization at the deadline itself is rejected");
  }
  await advanceToTimestamp(provider, Number(challengeDeadline) + 1);
  await (await game.finalizeUnchallenged(taskId, FINALIZE_GAS)).wait();
  const status = await game.getTaskStatus(taskId);
  assert.equal(Number(status[0]), 3);
  assert.equal(Number(status[1]), 1, "an unchallenged task finalizes as accepted");
});
