import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceTime,
  advanceToTimestamp,
  chainTimestamp,
  createProvider,
  onExternalChain,
  HEAVY_WINDOW_SECONDS,
  PAST_WINDOW_SECONDS,
  revertMatcher,
  signerFor,
  WINDOW_SECONDS
} from "./chain-harness.mjs";
import { ethers } from "ethers";
import {
  boundCreateTaskArgs,
  buildAuditTranscript,
  buildMerkleTree,
  challengeErrorDigest,
  ciphertextHandleForClear,
  compileContracts,
  computeBoundResultHash,
  getSubtreeChildren,
  leafHash,
  merkleProofForLeafHashTree,
  mutateLeafClaim,
  selectAuditDiligenceCheckpoint,
  terminalOutputBinding,
  traceLeafClaim,
  verifyPublishedOutputBinding,
  sampleTaskParticipants
} from "../../scripts/evm-lib.mjs";

const mnemonic = "test test test test test test test test test test test junk";
/**
 * Chain id of the in-process EVM. `createProvider` is asked for exactly this
 * id, so it is right there and only there.
 *
 * Do NOT use it to build an EIP-712 domain or to predict what the contract will
 * read from `block.chainid`: against an external chain the suite runs on that
 * chain's id (46853 for the four-validator QBFT network), and a hardcoded
 * 31337 makes the signatures verify against the wrong domain and the
 * leaf-decision binding assertion compare against the wrong bytes. Read the id
 * from the provider instead, as `attestedChainId` below does.
 */
const IN_PROCESS_CHAIN_ID = 31337;

/** The chain id the suite is actually running against. */
async function currentChainId(provider) {
  return Number((await provider.getNetwork()).chainId);
}


const leaves = [
  { opcode: 1, lhs: 12, rhs: 5, claimed: 60 },
  { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
  { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
];

/**
 * @param {object}  [options]
 * @param {boolean} [options.withLocalFhevm]
 * @param {number}  [options.windowSeconds]  protocol window for this fixture.
 *   Defaults to `WINDOW_SECONDS`. A test that drives SEVERAL tasks through the
 *   same phase needs more: on a real chain every transaction costs a block, the
 *   tasks are created one after another so their windows are staggered, and the
 *   opening work for three tasks is roughly eighteen sequential transactions.
 *   That does not fit a single window, and the phase expires mid-sequence with a
 *   revert unrelated to what the test asserts. `HEAVY_WINDOW_SECONDS` exists for
 *   exactly this and is a no-op on the in-process EVM, whose clock only moves
 *   when a test asks it to.
 */
async function deployFixture({ withLocalFhevm = false, windowSeconds = WINDOW_SECONDS } = {}) {
  const provider = await createProvider({ totalAccounts: 12, chainId: IN_PROCESS_CHAIN_ID });

  const deployer = await signerFor(provider, 0);
  const operator = await signerFor(provider, 1);
  const auditor1 = await signerFor(provider, 2);
  const auditor2 = await signerFor(provider, 3);
  const auditor3 = await signerFor(provider, 4);
  const decryptor1 = await signerFor(provider, 5);
  const decryptor2 = await signerFor(provider, 6);
  const decryptor3 = await signerFor(provider, 7);
  const reporter = await signerFor(provider, 8);

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
  const game = await gameFactory.deploy(
    await verifier.getAddress(), windowSeconds, windowSeconds, windowSeconds, false
  );
  await game.waitForDeployment();

  const availabilityFactory = new ethers.ContractFactory(
    artifacts.TraceAvailability.abi,
    artifacts.TraceAvailability.bytecode,
    deployer
  );
  const availability = await availabilityFactory.deploy(await game.getAddress(), windowSeconds);
  await availability.waitForDeployment();
  await (await game.setAvailabilityModule(await availability.getAddress())).wait();

  const localFhevm = withLocalFhevm
    ? await deployLocalFhevmRuntime(artifacts, deployer)
    : null;
  if (localFhevm) {
    await (
      await game.setFhevmVerifier(await localFhevm.fhevmVerifier.getAddress())
    ).wait();
  }

  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  await (await game.connect(auditor1).registerAuditor({ value: ethers.parseEther("1") })).wait();
  await (await game.connect(auditor2).registerAuditor({ value: ethers.parseEther("1") })).wait();
  await (await game.connect(auditor3).registerAuditor({ value: ethers.parseEther("1") })).wait();
  await (await game.connect(decryptor1).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  await (await game.connect(decryptor2).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  await (await game.connect(decryptor3).registerDecryptor({ value: ethers.parseEther("1") })).wait();

  return {
    artifacts,
    provider,
    deployer,
    game,
    availability,
    verifier,
    operator,
    auditors: [auditor1, auditor2, auditor3],
    decryptors: [decryptor1, decryptor2, decryptor3],
    reporter,
    localFhevm
  };
}

async function assignedWallets(game, taskId, wallets, getter) {
  const addresses = await game[getter](taskId);
  return addresses.map((address) =>
    wallets.find((wallet) => wallet.address.toLowerCase() === address.toLowerCase())
  );
}

async function assignedWalletsForLeaf(game, taskId, leafIndex, wallets) {
  const addresses = await game.getAssignedAuditorsForLeaf(taskId, leafIndex);
  return addresses.map((address) =>
    wallets.find((wallet) => wallet.address.toLowerCase() === address.toLowerCase())
  );
}

async function firstAssignedLeaf(game, taskId, auditor, leafCount = leaves.length, preferred = 0) {
  if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, preferred)) {
    return preferred;
  }
  for (let leafIndex = 0; leafIndex < leafCount; leafIndex += 1) {
    if (await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafIndex)) {
      return leafIndex;
    }
  }
  throw new Error(`No assigned leaf for auditor ${auditor.address}`);
}

async function commitAudit(game, taskId, auditor, verdict, podRoot, auditedLeafIndex) {
  const resolvedAuditedLeafIndex =
    auditedLeafIndex ?? (await firstAssignedLeaf(game, taskId, auditor));
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
    await game.connect(auditor).submitAudit(
      taskId,
      resolvedAuditedLeafIndex,
      podRoot,
      verdictCommit
    )
  ).wait();
  return { salt, podRoot, verdict, auditedLeafIndex: resolvedAuditedLeafIndex };
}

function buildChallengeAuditTranscript(
  taskId,
  auditor,
  operatorTraceRoot,
  leafIndex,
  operatorLeaf,
  recomputedLeaf
) {
  const errorDigest = challengeErrorDigest(taskId, leafIndex, operatorLeaf, recomputedLeaf);
  const auditTraceLeaf = {
    leafIndex,
    operatorLeafHash: leafHash(operatorLeaf),
    recomputedLeafHash: leafHash(recomputedLeaf),
    errorDigest
  };
  return {
    errorDigest,
    ...buildAuditTranscript({
      taskId,
      auditorAddress: auditor.address,
      operatorTraceRoot,
      auditTraceLeaf,
      operatorLeaf,
      recomputedLeaf
    })
  };
}

async function proveDiligence(game, taskId, auditor, auditTranscript) {
  await sealDiligenceRandomness(game, taskId);
  return proveDiligenceWithSealedSeed(game, taskId, auditor, auditTranscript);
}

async function sealDiligenceRandomness(game, taskId) {
  await (await game.sealDiligenceRandomness(taskId)).wait();
}

async function proveDiligenceWithSealedSeed(game, taskId, auditor, auditTranscript) {
  const checkpointIndex = await game.getRequiredDiligenceCheckpointIndex(taskId, auditor.address);
  const selected = selectAuditDiligenceCheckpoint(auditTranscript, checkpointIndex);
  await (
    await game.connect(auditor).proveAuditDiligence(
      taskId,
      selected.diligenceCheckpoint,
      selected.diligenceProof,
      selected.diligenceProofSiblingOnLeft
    )
  ).wait();
  return selected;
}

async function claimDiligenceRewardWithSealedSeed(game, taskId, auditor, auditTranscript) {
  const checkpointIndex = await game.getRequiredDiligenceCheckpointIndex(taskId, auditor.address);
  const selected = selectAuditDiligenceCheckpoint(auditTranscript, checkpointIndex);
  await (
    await game.connect(auditor).claimDiligenceReward(
      taskId,
      selected.diligenceCheckpoint,
      selected.diligenceProof,
      selected.diligenceProofSiblingOnLeft
    )
  ).wait();
  return selected;
}

async function openCommittedAudit(game, taskId, auditor, auditCommitment, decryptors) {
  for (const decryptor of decryptors) {
    await (
      await game
        .connect(decryptor)
        .openVerdict(
          taskId,
          auditor.address,
          auditCommitment.verdict,
          auditCommitment.salt,
          auditCommitment.podRoot
        )
    ).wait();
  }
}

async function expectCallException(action, pattern) {
  try {
    const result = await action();
    if (result?.wait) {
      await result.wait();
    }
  } catch (error) {
    assert.equal(error.code, "CALL_EXCEPTION");
    if (pattern) {
      assert.match(error.message, pattern);
    }
    return;
  }
  assert.fail("expected CALL_EXCEPTION");
}

async function bisectAndResolve(
  game,
  taskId,
  operatorWallet,
  challengerWallet,
  operatorTree,
  challengerTree,
  operatorLeaf,
  challengerLeaf
) {
  let dispute = await game.getTaskDisputeState(taskId);
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const operatorChildren = getSubtreeChildren(operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challengerTree, start, end);

    await (
      await game
        .connect(operatorWallet)
        .submitBisection(taskId, true, operatorChildren.left, operatorChildren.right)
    ).wait();
    await (
      await game
        .connect(challengerWallet)
        .submitBisection(taskId, false, challengerChildren.left, challengerChildren.right)
    ).wait();
    await (await game.advanceDispute(taskId)).wait();
    dispute = await game.getTaskDisputeState(taskId);
  }

  await (
    // Handles only: `traceLeafClaim` strips the clear witness fields the test
    // fixtures carry, so nothing but (opcode, lhsHandle, rhsHandle,
    // claimedHandle) reaches calldata.
    await game.resolveLeafDispute(
      taskId,
      traceLeafClaim(operatorLeaf),
      traceLeafClaim(challengerLeaf)
    )
  ).wait();
}

async function bisectToLeaf(
  game,
  taskId,
  operatorWallet,
  challengerWallet,
  operatorTree,
  challengerTree
) {
  let dispute = await game.getTaskDisputeState(taskId);
  while (Number(dispute.disputeEnd) - Number(dispute.disputeStart) > 1) {
    const start = Number(dispute.disputeStart);
    const end = Number(dispute.disputeEnd);
    const operatorChildren = getSubtreeChildren(operatorTree, start, end);
    const challengerChildren = getSubtreeChildren(challengerTree, start, end);

    await (
      await game
        .connect(operatorWallet)
        .submitBisection(taskId, true, operatorChildren.left, operatorChildren.right)
    ).wait();
    await (
      await game
        .connect(challengerWallet)
        .submitBisection(taskId, false, challengerChildren.left, challengerChildren.right)
    ).wait();
    await (await game.advanceDispute(taskId)).wait();
    dispute = await game.getTaskDisputeState(taskId);
  }

  return dispute;
}

async function deployLocalFhevmRuntime(artifacts, deployer) {
  const aclFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmACL.abi,
    artifacts.LocalFhevmACL.bytecode,
    deployer
  );
  const acl = await aclFactory.deploy();
  await acl.waitForDeployment();

  const executorFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmExecutor.abi,
    artifacts.LocalFhevmExecutor.bytecode,
    deployer
  );
  const executor = await executorFactory.deploy();
  await executor.waitForDeployment();

  const kmsFactory = new ethers.ContractFactory(
    artifacts.LocalFhevmKMSVerifier.abi,
    artifacts.LocalFhevmKMSVerifier.bytecode,
    deployer
  );
  const kms = await kmsFactory.deploy(await acl.getAddress(), await executor.getAddress());
  await kms.waitForDeployment();

  const fhevmVerifierFactory = new ethers.ContractFactory(
    artifacts.FhevmObjectiveMicroVerifier.abi,
    artifacts.FhevmObjectiveMicroVerifier.bytecode,
    deployer
  );
  const fhevmVerifier = await fhevmVerifierFactory.deploy(
    await acl.getAddress(),
    await executor.getAddress(),
    await kms.getAddress()
  );
  await fhevmVerifier.waitForDeployment();

  return { acl, executor, kms, fhevmVerifier };
}

// Cross into the reveal (open) window. When the task is supplied, advance to
// just past the on-chain commit deadline instead of by a fixed delta from the
// current clock: on a slow-block chain a fixed overshoot can consume most of
// the open window before the reveal transactions are sent, so the later
// openVerdict calls land past the open deadline and revert with WrongPhase.
// Advancing relative to the deadline gives the open phase the full window.
/**
 * Move into the opening window of `taskId`, that is, just past its commit
 * deadline.
 *
 * ALWAYS pass `game` and `taskId`, for the same reason as
 * `advancePastOpenWindow` below: the deadline is absolute, the commit
 * transactions that precede this call have already consumed part of the window
 * on a real chain, and a relative wait from "now" overshoots by that much. Here
 * the overshoot lands past the OPENING deadline, so the `openVerdict` calls
 * that follow would revert. The relative branch is kept only for callers with
 * no task at hand.
 */
async function advanceToRevealWindow(provider, game, taskId) {
  if (game && taskId) {
    const [commitDeadline] = await game.getTaskDeadlines(taskId);
    await advanceToTimestamp(provider, Number(commitDeadline) + 1);
    return;
  }
  await advanceTime(provider, PAST_WINDOW_SECONDS);
}

/**
 * Move past the opening deadline of `taskId`.
 *
 * ALWAYS pass `game` and `taskId`. The deadline is an ABSOLUTE timestamp fixed
 * when the task was created, and on a real chain the audit and opening
 * transactions that precede this call have already consumed part of that
 * window. Waiting a RELATIVE `PAST_WINDOW_SECONDS` from "now" therefore
 * overshoots by however long those transactions took, and lands past the
 * challenge deadline as well, so the `openChallenge` that follows reverts for a
 * reason that has nothing to do with what the test is asserting. Measured on
 * the four-validator QBFT network, that is exactly how "bisection rejects
 * subtree hashes..." and "false challenger gets slashed..." failed, both after
 * roughly 390 s of real chain time.
 *
 * The relative branch is kept only for callers with no task at hand.
 */
async function advancePastOpenWindow(provider, game, taskId) {
  if (game && taskId) {
    const [, openDeadline] = await game.getTaskDeadlines(taskId);
    await advanceToTimestamp(provider, Number(openDeadline) + 1);
    return;
  }
  await advanceTime(provider, PAST_WINDOW_SECONDS);
}

async function advancePastChallengeWindow(provider) {
  await advanceTime(provider, 2 * WINDOW_SECONDS + 1);
}

test("optimistic path finalizes when no auditor opens a challenge", async () => {
  const { provider, game, verifier, operator, auditors, decryptors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("happy");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, ethers.id("result-happy")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        true,
        ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:happy`))
      )
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(taskId)).wait();

  const task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.decision), 1);
  assert.equal(Number(task.status), 3);

  await assert.rejects(
    game.setFhevmVerifier(await verifier.getAddress()),
    revertMatcher(game, "InvalidFhevmVerifierMode")
  );
});

test("createTask rejects a result hash that is not bound to the terminal trace state", async () => {
  const { game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("result-unbound");
  const attestation = ethers.id("unrelated-output");
  const binding = terminalOutputBinding(taskId, tree, leaves, attestation);

  // Legacy behavior: an arbitrary, unbound result hash must now revert.
  await expectCallException(() =>
    game
      .connect(operator)
      .createTask(
        taskId,
        tree.root,
        ethers.id("unrelated-output"),
        tree.leafCount,
        binding.terminalLeaf,
        binding.terminalLeafProof,
        attestation
      )
  );

  // Output substitution: a result hash bound to a value different from the
  // terminal trace state must revert.
  const substitutedHash = computeBoundResultHash(
    taskId,
    tree.root,
    tree.leafCount,
    ciphertextHandleForClear(999),
    attestation
  );
  await expectCallException(() =>
    game
      .connect(operator)
      .createTask(
        taskId,
        tree.root,
        substitutedHash,
        tree.leafCount,
        binding.terminalLeaf,
        binding.terminalLeafProof,
        attestation
      )
  );

  // Position pinning: a proof for a non-terminal leaf must revert even when
  // the result hash consistently commits to that leaf's claimed value.
  const nonTerminalLeaf = leaves[0];
  const nonTerminalProof = merkleProofForLeafHashTree(tree, 0).proof;
  const nonTerminalHash = computeBoundResultHash(
    taskId,
    tree.root,
    tree.leafCount,
    traceLeafClaim(nonTerminalLeaf).claimedHandle,
    attestation
  );
  await expectCallException(() =>
    game
      .connect(operator)
      .createTask(
        taskId,
        tree.root,
        nonTerminalHash,
        tree.leafCount,
        traceLeafClaim(nonTerminalLeaf),
        nonTerminalProof,
        attestation
      )
  );

  // A zero output attestation must revert.
  const zeroAttestationHash = computeBoundResultHash(
    taskId,
    tree.root,
    tree.leafCount,
    traceLeafClaim(leaves[leaves.length - 1]).claimedHandle,
    ethers.ZeroHash
  );
  await expectCallException(() =>
    game
      .connect(operator)
      .createTask(
        taskId,
        tree.root,
        zeroAttestationHash,
        tree.leafCount,
        binding.terminalLeaf,
        binding.terminalLeafProof,
        ethers.ZeroHash
      )
  );
});

test("published output binding is traceable and externally verifiable", async () => {
  const { provider, game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("result-bound");
  const attestation = ethers.id("published-ciphertext-attestation");
  // The binding now commits to the terminal output HANDLE: the trace commits
  // to handles, so there is no clear terminal value on the leaf to bind, and a
  // chain adjudicating encrypted execution could not read one anyway. A
  // consumer checks that the ciphertext it received hashes to this handle.
  const publishedOutputHandle = traceLeafClaim(leaves[leaves.length - 1]).claimedHandle;

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, attestation))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  // On-chain binding view matches the canonical off-chain derivation.
  const bindingView = await game.getTaskResultBinding(taskId);
  assert.equal(
    bindingView.resultHash.toLowerCase(),
    computeBoundResultHash(
      taskId,
      tree.root,
      tree.leafCount,
      publishedOutputHandle,
      attestation
    ).toLowerCase()
  );
  assert.equal(bindingView.operatorTraceRoot.toLowerCase(), tree.root.toLowerCase());
  assert.equal(Number(bindingView.leafCount), tree.leafCount);

  // A consumer holding the published output and attestation can verify it.
  assert.equal(
    verifyPublishedOutputBinding({
      taskId,
      operatorTraceRoot: bindingView.operatorTraceRoot,
      leafCount: Number(bindingView.leafCount),
      publishedOutputHandle,
      outputAttestationHash: attestation,
      onChainResultHash: bindingView.resultHash
    }),
    true
  );

  // A substituted output ciphertext fails consumer-side verification.
  assert.equal(
    verifyPublishedOutputBinding({
      taskId,
      operatorTraceRoot: bindingView.operatorTraceRoot,
      leafCount: Number(bindingView.leafCount),
      publishedOutputHandle: ciphertextHandleForClear(
        BigInt(leaves[leaves.length - 1].claimed) + 1n
      ),
      outputAttestationHash: attestation,
      onChainResultHash: bindingView.resultHash
    }),
    false
  );

  // The creation event logs the bound terminal output and attestation.
  // Bound the log range: a real node caps eth_getLogs spans, and the default
  // query would run from genesis. The event of interest is recent by
  // construction, so a short window back from the head is sufficient.
  // A real node caps eth_getLogs spans, so bound the range there; the
  // in-process chain is short-lived and is queried from genesis.
  const headBlock = await provider.getBlockNumber();
  const boundEvents = await game.queryFilter(
    game.filters.TerminalOutputBound(taskId),
    onExternalChain ? Math.max(0, headBlock - 500) : 0,
    "latest"
  );
  assert.equal(boundEvents.length, 1);
  assert.equal(
    boundEvents[0].args.terminalOutputHandle.toLowerCase(),
    publishedOutputHandle.toLowerCase()
  );
  assert.equal(
    boundEvents[0].args.outputAttestationHash.toLowerCase(),
    attestation.toLowerCase()
  );

  // The bound task still finalizes optimistically when unchallenged.
  await advanceToRevealWindow(provider, game, taskId);
  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(taskId)).wait();
  const task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.decision), 1);
  assert.equal(Number(task.status), 3);
});

test("one dissenting auditor can slash the operator even if the other auditors support the operator", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("bad-operator");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-bad")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
      taskId,
      auditor.address,
      leafHint
    );
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:supports=${supportsOperator}`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        auditorCoversChallengedLeaf ? leafHint : undefined
      )
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  const requiredBond = (await game.getParticipantStakeBreakdown(challenger.address)).lockedChallengeBondWei;
  const challengerBondDuringDispute = await game.getParticipantStakeBreakdown(challenger.address);
  const challenge = await game.getChallengeClaim(taskId);
  assert.equal(challenge.challenger, challenger.address);
  assert.equal(challenge.challengerTraceRoot, challengerTree.root);
  assert.equal(Number(challenge.challengeLeafHint), leafHint);
  assert.equal(challenge.challengeErrorDigest, challengeTranscript.errorDigest);
  assert.equal(challenge.challengePodRoot, challengeTranscript.root);
  assert.equal(challenge.challengeAuditLeafHash, challengeTranscript.leafHash);
  assert.equal(challengerBondDuringDispute.lockedChallengeBondWei, requiredBond);
  assert.equal(
    challengerBondDuringDispute.availableStakeWei,
    challengerBondDuringDispute.totalStakeWei - requiredBond
  );
  assert.equal(
    challengeErrorDigest(
      taskId,
      leafHint,
      traceLeafClaim(badLeaf),
      traceLeafClaim(leaves[2])
    ),
    challengeTranscript.errorDigest
  );

  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  const wrongAuditor = leafAuditors.find((auditor) => auditor.address !== challenger.address);
  const wrongAuditorStakeBefore = await game.getParticipantStake(wrongAuditor.address);

  await bisectAndResolve(
    game,
    taskId,
    operator,
    challenger,
    operatorTree,
    challengerTree,
    badLeaf,
    leaves[2]
  );

  const task = await game.getTaskStatus(taskId);
  const operatorStakeAfter = await game.getParticipantStake(operator.address);
  const challengerStakeAfter = await game.getParticipantStake(challenger.address);
  const wrongAuditorStakeAfter = await game.getParticipantStake(wrongAuditor.address);
  const wrongAuditRecord = await game.getAuditStatus(taskId, wrongAuditor.address);
  const challengerBondAfterResolution = await game.getParticipantStakeBreakdown(challenger.address);

  assert.equal(Number(task.decision), 2);
  assert.equal(Number(task.status), 3);
  assert.equal(operatorStakeAfter, operatorStakeBefore - ethers.parseEther("0.5"));
  assert.equal(wrongAuditorStakeAfter, wrongAuditorStakeBefore - ethers.parseEther("0.5"));
  assert.equal(challengerStakeAfter, challengerStakeBefore + ethers.parseEther("1.0"));
  assert.equal(challengerBondAfterResolution.lockedChallengeBondWei, 0n);
  assert.equal(wrongAuditRecord.wrongVerdictSlashed, true);
});

test("wrong-verdict slashing only applies to auditors scoped to the challenged stage", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("stage-scope");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-stage")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const stageAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = stageAuditors[0];
  const sameStageWrongAuditor = stageAuditors[1];
  const otherStageAuditor = assignedAuditors.find(
    (auditor) => !stageAuditors.some((stageAuditor) => stageAuditor.address === auditor.address)
  );
  const otherStageLeaf = await firstAssignedLeaf(game, taskId, otherStageAuditor, leaves.length, 0);
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const isChallenger = auditor.address === challenger.address;
    const isSameStageWrongAuditor = auditor.address === sameStageWrongAuditor.address;
    const auditedLeafIndex = isChallenger || isSameStageWrongAuditor ? leafHint : otherStageLeaf;
    const podRoot = isChallenger
      ? challengeTranscript.root
      : ethers.keccak256(
          ethers.toUtf8Bytes(`pod:${auditor.address}:stage=${auditedLeafIndex}`)
        );
    auditCommitments.push(
      await commitAudit(game, taskId, auditor, !isChallenger, podRoot, auditedLeafIndex)
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  const sameStageStakeBefore = await game.getParticipantStake(sameStageWrongAuditor.address);
  const otherStageStakeBefore = await game.getParticipantStake(otherStageAuditor.address);

  await bisectAndResolve(
    game,
    taskId,
    operator,
    challenger,
    operatorTree,
    challengerTree,
    badLeaf,
    leaves[2]
  );

  const sameStageStakeAfter = await game.getParticipantStake(sameStageWrongAuditor.address);
  const otherStageStakeAfter = await game.getParticipantStake(otherStageAuditor.address);
  const sameStageRecord = await game.getAuditStatus(taskId, sameStageWrongAuditor.address);
  const otherStageRecord = await game.getAuditStatus(taskId, otherStageAuditor.address);

  assert.equal(sameStageStakeAfter, sameStageStakeBefore - ethers.parseEther("0.5"));
  assert.equal(otherStageStakeAfter, otherStageStakeBefore);
  assert.equal(sameStageRecord.wrongVerdictSlashed, true);
  assert.equal(otherStageRecord.wrongVerdictSlashed, false);
  assert.equal(Number(sameStageRecord.auditedLeafIndex), leafHint);
  assert.equal(Number(otherStageRecord.auditedLeafIndex), otherStageLeaf);
});

test("challenge must reveal an audit trace leaf committed by the PoD root", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("bad-pod-proof");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-bad-pod")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const [challenger] = await assignedWalletsForLeaf(game, taskId, 2, auditors);
  const transcript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    2,
    badLeaf,
    leaves[2]
  );
  const auditCommitment = await commitAudit(game, taskId, challenger, false, transcript.root, 2);

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, transcript);

  const badAuditProof = [...transcript.proof];
  badAuditProof[0] = ethers.keccak256(ethers.toUtf8Bytes("fake-audit-sibling"));
  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      2,
      transcript.errorDigest,
      transcript.leaves[0],
      badAuditProof,
      transcript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|bad audit proof/
  );
});

test("challenge cannot pass diligence with a PoD root that omits the checkpoint", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("bad-pod-root");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-bad-pod-root")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const [challenger] = await assignedWalletsForLeaf(game, taskId, 2, auditors);
  const transcript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    2,
    badLeaf,
    leaves[2]
  );
  const wrongPodRoot = ethers.keccak256(ethers.toUtf8Bytes("not-the-audit-transcript"));
  const auditCommitment = await commitAudit(game, taskId, challenger, false, wrongPodRoot, 2);

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );

  await advancePastOpenWindow(provider, game, taskId);
  await sealDiligenceRandomness(game, taskId);
  const badCheckpointIndex = await game.getRequiredDiligenceCheckpointIndex(
    taskId,
    challenger.address
  );
  const badSelected = selectAuditDiligenceCheckpoint(transcript, badCheckpointIndex);
  await assert.rejects(
    game.connect(challenger).proveAuditDiligence(
      taskId,
      badSelected.diligenceCheckpoint,
      badSelected.diligenceProof,
      badSelected.diligenceProofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|bad diligence proof/
  );
  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      2,
      transcript.errorDigest,
      transcript.leaves[0],
      transcript.proof,
      transcript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|diligence not proven/
  );
});

test("challenge reward path requires a precommitted diligence checkpoint", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("pod-checkpoint");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-pod-check")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [challenger] = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );

  const auditCommitment = await commitAudit(
    game,
    taskId,
    challenger,
    false,
    challengeTranscript.root,
    leafHint
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);

  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|diligence not proven/
  );

  await (await game.sealDiligenceRandomness(taskId)).wait();
  const checkpointIndex = await game.getRequiredDiligenceCheckpointIndex(
    taskId,
    challenger.address
  );
  const wrongCheckpointIndex =
    (Number(checkpointIndex) + 1) % challengeTranscript.diligenceCheckpoints.length;
  const wrongSelected = selectAuditDiligenceCheckpoint(
    challengeTranscript,
    wrongCheckpointIndex
  );
  await assert.rejects(
    game.connect(challenger).proveAuditDiligence(
      taskId,
      wrongSelected.diligenceCheckpoint,
      wrongSelected.diligenceProof,
      wrongSelected.diligenceProofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|wrong diligence checkpoint/
  );

  const selected = selectAuditDiligenceCheckpoint(challengeTranscript, checkpointIndex);
  await (
    await game.connect(challenger).proveAuditDiligence(
      taskId,
      selected.diligenceCheckpoint,
      selected.diligenceProof,
      selected.diligenceProofSiblingOnLeft
    )
  ).wait();
  const auditStatus = await game.getAuditStatus(taskId, challenger.address);
  assert.equal(auditStatus.diligenceProven, true);
  assert.equal(auditStatus.diligenceCheckpointHash, selected.diligenceCheckpointHash);
});

test("diligence randomness cannot be sealed before audit commitments are fixed", async () => {
  const { game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("early-seed");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, ethers.id("result-early-seed")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  await expectCallException(
    () => game.sealDiligenceRandomness(taskId),
    /CALL_EXCEPTION|transaction execution reverted|commit phase active/
  );
});

test("diligence randomness is post-commit, single-use, and required before diligence proofs", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("pod-seed");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-pod-seed")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [challenger] = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const transcript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );
  const auditCommitment = await commitAudit(
    game,
    taskId,
    challenger,
    false,
    transcript.root,
    leafHint
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);

  const firstCheckpoint = selectAuditDiligenceCheckpoint(transcript, 0);
  await assert.rejects(
    game.connect(challenger).proveAuditDiligence(
      taskId,
      firstCheckpoint.diligenceCheckpoint,
      firstCheckpoint.diligenceProof,
      firstCheckpoint.diligenceProofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|diligence randomness missing/
  );

  await sealDiligenceRandomness(game, taskId);
  const challengeBefore = await game.getChallengeClaim(taskId);
  assert.notEqual(challengeBefore.diligenceSeed, ethers.ZeroHash);

  const selected = await proveDiligenceWithSealedSeed(game, taskId, challenger, transcript);
  assert.ok(Number(selected.diligenceCheckpoint.checkpointIndex) >= 0);

  await expectCallException(
    () => game.sealDiligenceRandomness(taskId),
    /CALL_EXCEPTION|transaction execution reverted|diligence randomness sealed/
  );

  await expectCallException(
    () => game.connect(challenger).proveAuditDiligence(
      taskId,
      selected.diligenceCheckpoint,
      selected.diligenceProof,
      selected.diligenceProofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|diligence already proven/
  );

  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      transcript.errorDigest,
      transcript.leaves[0],
      transcript.proof,
      transcript.proofSiblingOnLeft
    )
  ).wait();
});

test("diligence checkpoints are bound to the auditor identity and cannot be replayed", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("pod-replay");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-pod-replay")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [honestAuditor, replayingAuditor] = await assignedWalletsForLeaf(
    game,
    taskId,
    leafHint,
    auditors
  );
  const honestTranscript = buildChallengeAuditTranscript(
    taskId,
    honestAuditor,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );
  const honestCommitment = await commitAudit(
    game,
    taskId,
    honestAuditor,
    false,
    honestTranscript.root,
    leafHint
  );
  const replayingCommitment = await commitAudit(
    game,
    taskId,
    replayingAuditor,
    false,
    honestTranscript.root,
    leafHint
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    honestAuditor,
    honestCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await openCommittedAudit(
    game,
    taskId,
    replayingAuditor,
    replayingCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await sealDiligenceRandomness(game, taskId);

  const replayCheckpointIndex = await game.getRequiredDiligenceCheckpointIndex(
    taskId,
    replayingAuditor.address
  );
  const replayedSelected = selectAuditDiligenceCheckpoint(
    honestTranscript,
    replayCheckpointIndex
  );
  await assert.rejects(
    game.connect(replayingAuditor).proveAuditDiligence(
      taskId,
      replayedSelected.diligenceCheckpoint,
      replayedSelected.diligenceProof,
      replayedSelected.diligenceProofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|bad diligence proof/
  );
});

test("auditors cannot submit or challenge outside their assigned stage", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("stage-bound");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-stage-bound")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const targetLeaf = 2;
  const stageAuditors = await assignedWalletsForLeaf(game, taskId, targetLeaf, auditors);
  const outOfStageAuditor = auditors.find(
    (auditor) => !stageAuditors.some((stageAuditor) => stageAuditor.address === auditor.address)
  );
  const assignedLeaf = await firstAssignedLeaf(game, taskId, outOfStageAuditor, leaves.length, 0);
  const wrongScopeTranscript = buildChallengeAuditTranscript(
    taskId,
    outOfStageAuditor,
    operatorTree.root,
    assignedLeaf,
    operatorLeaves[assignedLeaf],
    leaves[assignedLeaf]
  );

  await assert.rejects(
    commitAudit(
      game,
      taskId,
      outOfStageAuditor,
      false,
      wrongScopeTranscript.root,
      targetLeaf
    ),
    /CALL_EXCEPTION|transaction execution reverted|auditor not assigned to leaf/
  );

  const commitment = await commitAudit(
    game,
    taskId,
    outOfStageAuditor,
    false,
    wrongScopeTranscript.root,
    assignedLeaf
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    outOfStageAuditor,
    commitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, outOfStageAuditor, wrongScopeTranscript);

  await assert.rejects(
    game.connect(outOfStageAuditor).openChallenge(
      taskId,
      buildMerkleTree(leaves).root,
      targetLeaf,
      wrongScopeTranscript.errorDigest,
      wrongScopeTranscript.leaves[0],
      wrongScopeTranscript.proof,
      wrongScopeTranscript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|auditor not scoped to leaf/
  );
});

test("supporting auditors cannot convert a pro-operator verdict into a reward-bearing challenge", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("no-dissent");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-no-dissent")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [auditor] = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const transcript = buildChallengeAuditTranscript(
    taskId,
    auditor,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );
  const auditCommitment = await commitAudit(game, taskId, auditor, true, transcript.root, leafHint);

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    auditor,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, auditor, transcript);

  await assert.rejects(
    game.connect(auditor).openChallenge(
      taskId,
      buildMerkleTree(leaves).root,
      leafHint,
      transcript.errorDigest,
      transcript.leaves[0],
      transcript.proof,
      transcript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|no dissent/
  );
});

test("challenge evidence must match the recomputed leaf revealed in the diligence checkpoint", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const tamperedRecomputedLeaf = mutateLeafClaim(leaves[2], { claimed: 9 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("pod-mismatch");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-pod-mismatch")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [challenger] = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const tamperedErrorDigest = challengeErrorDigest(
    taskId,
    leafHint,
    badLeaf,
    tamperedRecomputedLeaf
  );
  const tamperedAuditTraceLeaf = {
    leafIndex: leafHint,
    operatorLeafHash: leafHash(badLeaf),
    recomputedLeafHash: leafHash(tamperedRecomputedLeaf),
    errorDigest: tamperedErrorDigest
  };
  const transcript = buildAuditTranscript({
    taskId,
    auditorAddress: challenger.address,
    operatorTraceRoot: operatorTree.root,
    auditTraceLeaf: tamperedAuditTraceLeaf,
    operatorLeaf: badLeaf,
    recomputedLeaf: leaves[leafHint]
  });
  const auditCommitment = await commitAudit(
    game,
    taskId,
    challenger,
    false,
    transcript.root,
    leafHint
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, transcript);

  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      tamperedErrorDigest,
      transcript.leaves[0],
      transcript.proof,
      transcript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|diligence hash mismatch/
  );
});

test("bisection rejects subtree hashes that do not match committed trace roots", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("bad-subtree");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-bad-subtree")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const [challenger] = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
      taskId,
      auditor.address,
      leafHint
    );
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:bad-subtree`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        auditorCoversChallengedLeaf ? leafHint : undefined
      )
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  const dispute = await game.getTaskDisputeState(taskId);
  const start = Number(dispute.disputeStart);
  const end = Number(dispute.disputeEnd);
  const operatorChildren = getSubtreeChildren(operatorTree, start, end);
  const challengerChildren = getSubtreeChildren(challengerTree, start, end);
  const fakeLeft = ethers.keccak256(ethers.toUtf8Bytes("fake-left-branch"));

  await assert.rejects(
    game.connect(operator).submitBisection(taskId, true, fakeLeft, operatorChildren.right),
    /CALL_EXCEPTION|transaction execution reverted|bad operator branch/
  );
  await (
    await game
      .connect(operator)
      .submitBisection(taskId, true, operatorChildren.left, operatorChildren.right)
  ).wait();

  await assert.rejects(
    game.connect(challenger).submitBisection(taskId, false, fakeLeft, challengerChildren.right),
    /CALL_EXCEPTION|transaction execution reverted|bad challenger branch/
  );
  await (
    await game
      .connect(challenger)
      .submitBisection(taskId, false, challengerChildren.left, challengerChildren.right)
  ).wait();

  await (await game.advanceDispute(taskId)).wait();
  const updated = await game.getTaskDisputeState(taskId);
  assert.equal(Number(updated.disputeStart), 2);
  assert.equal(Number(updated.disputeEnd), 4);
});

// A single Sybil seat in the cohort must not be able to burn the task's
// challenge. Before this rule, one challenge per task was allowed and any
// lost challenge finalized the task with the operator's result standing, so
// an operator-controlled auditor could open a deliberately losing challenge
// first (its bond flowing back to the operator) and lock out the honest
// dissenter of the same cohort. Now a lost challenge returns the task to
// Auditing, bars the loser, and the honest auditor's challenge proceeds.
test("a sham losing challenge does not consume the task's challenge: the honest dissenter still wins", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = mutateLeafClaim(leaves[2], { claimed: 6 }); // corrupted leaf
  const operatorTree = buildMerkleTree(operatorLeaves);
  const honestTree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("sham-challenge");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-sham")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors");
  const leafTwoAuditors = await assignedWalletsForLeaf(game, taskId, 2, auditors);
  // The sham targets a CORRECT leaf that precedes the corrupted one, so that
  // bisection between the operator's tree and the sham tree isolates it.
  let sham = null;
  let shamLeaf = -1;
  let honest = null;
  for (const k of [0, 1]) {
    const candidates = await assignedWalletsForLeaf(game, taskId, k, auditors);
    for (const c of candidates) {
      const h = leafTwoAuditors.find((w) => w.address !== c.address);
      if (h) {
        sham = c;
        shamLeaf = k;
        honest = h;
        break;
      }
    }
    if (sham) break;
  }
  assert.ok(sham && honest, "fixture must yield a sham seat on a correct leaf and a distinct honest seat on leaf 2");

  const shamBadLeaf = mutateLeafClaim(leaves[shamLeaf], { claimed: 99 });
  const shamLeaves = [...leaves];
  shamLeaves[shamLeaf] = shamBadLeaf;
  const shamTree = buildMerkleTree(shamLeaves);
  const shamTranscript = buildChallengeAuditTranscript(
    taskId, sham, operatorTree.root, shamLeaf, operatorLeaves[shamLeaf], shamBadLeaf
  );
  const honestTranscript = buildChallengeAuditTranscript(
    taskId, honest, operatorTree.root, 2, operatorLeaves[2], leaves[2]
  );

  const commitments = new Map();
  for (const auditor of assignedAuditors) {
    if (auditor.address === sham.address) {
      commitments.set(auditor.address, await commitAudit(game, taskId, auditor, false, shamTranscript.root, shamLeaf));
    } else if (auditor.address === honest.address) {
      commitments.set(auditor.address, await commitAudit(game, taskId, auditor, false, honestTranscript.root, 2));
    } else {
      const podRoot = ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:supports:sham-test`));
      commitments.set(auditor.address, await commitAudit(game, taskId, auditor, true, podRoot));
    }
  }
  await advanceToRevealWindow(provider, game, taskId);
  for (const auditor of assignedAuditors) {
    await openCommittedAudit(game, taskId, auditor, commitments.get(auditor.address), assignedDecryptors.slice(0, 2));
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, sham, shamTranscript);
  await proveDiligenceWithSealedSeed(game, taskId, honest, honestTranscript);

  // ---- sham challenge: loses at the correct leaf ---------------------------
  const operatorStake0 = await game.getParticipantStake(operator.address);
  const shamStake0 = await game.getParticipantStake(sham.address);
  await (
    await game.connect(sham).openChallenge(
      taskId, shamTree.root, shamLeaf, shamTranscript.errorDigest,
      shamTranscript.leaves[0], shamTranscript.proof, shamTranscript.proofSiblingOnLeft
    )
  ).wait();
  await bisectAndResolve(game, taskId, operator, sham, operatorTree, shamTree, operatorLeaves[shamLeaf], shamBadLeaf);
  let task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.status), 1, "task re-opened after the sham lost");
  assert.equal(task.challengeTriggered, false);
  assert.equal(await game.getParticipantStake(operator.address), operatorStake0 + ethers.parseEther("0.5"));
  assert.equal(await game.getParticipantStake(sham.address), shamStake0 - ethers.parseEther("0.5"));

  // ---- honest challenge on the corrupted leaf: operator slashed -----------
  const honestStake0 = await game.getParticipantStake(honest.address);
  const shamStake1 = await game.getParticipantStake(sham.address);
  await (
    await game.connect(honest).openChallenge(
      taskId, honestTree.root, 2, honestTranscript.errorDigest,
      honestTranscript.leaves[0], honestTranscript.proof, honestTranscript.proofSiblingOnLeft
    )
  ).wait();
  await bisectAndResolve(game, taskId, operator, honest, operatorTree, honestTree, operatorLeaves[2], leaves[2]);
  task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.status), 3, "finalized");
  assert.equal(Number(task.decision), 2, "OperatorSlashed");
  assert.ok(
    (await game.getParticipantStake(honest.address)) > honestStake0,
    "the honest challenger is compensated from the slash"
  );
  assert.equal(
    await game.getParticipantStake(sham.address),
    shamStake1,
    "the sham challenger is not slashed twice (its bond was the penalty)"
  );
});

test("false challenger gets slashed when the operator leaf is objectively correct", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const operatorTree = buildMerkleTree(leaves);
  const badChallengerLeaf = mutateLeafClaim(leaves[2], { claimed: 6 });
  const challengerLeaves = [...leaves];
  challengerLeaves[2] = badChallengerLeaf;
  const challengerTree = buildMerkleTree(challengerLeaves);
  const taskId = ethers.encodeBytes32String("bad-challenger");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, leaves, ethers.id("result-ok")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const [challenger] = await assignedWalletsForLeaf(game, taskId, 2, auditors);
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    2,
    leaves[2],
    badChallengerLeaf
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
      taskId,
      auditor.address,
      2
    );
    const podRoot = supportsOperator
      ? ethers.keccak256(
          ethers.toUtf8Bytes(
            `pod:${auditor.address}:supports=${supportsOperator}:false-challenge`
          )
        )
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        auditorCoversChallengedLeaf ? 2 : undefined
      )
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      2,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  const requiredBond = (await game.getParticipantStakeBreakdown(challenger.address)).lockedChallengeBondWei;
  const challengerBondDuringDispute = await game.getParticipantStakeBreakdown(challenger.address);
  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  assert.equal(challengerBondDuringDispute.lockedChallengeBondWei, requiredBond);
  assert.equal(
    challengerBondDuringDispute.availableStakeWei,
    challengerBondDuringDispute.totalStakeWei - requiredBond
  );

  await bisectAndResolve(
    game,
    taskId,
    operator,
    challenger,
    operatorTree,
    challengerTree,
    leaves[2],
    badChallengerLeaf
  );

  const task = await game.getTaskStatus(taskId);
  const operatorStakeAfter = await game.getParticipantStake(operator.address);
  const challengerStakeAfter = await game.getParticipantStake(challenger.address);
  const challengerBondAfterResolution = await game.getParticipantStakeBreakdown(challenger.address);

  // A lost challenge no longer closes the task: it returns to Auditing so
  // that another eligible dissenter keeps its challenge, and the loser is
  // barred from challenging again. With no further challenge the task
  // finalizes as accepted once the (restarted) challenge window expires.
  assert.equal(Number(task.decision), 0, "no decision yet: the task re-opened");
  assert.equal(Number(task.status), 1, "task must be back in Auditing");
  assert.equal(task.challengeTriggered, false);
  assert.equal(operatorStakeAfter, operatorStakeBefore + ethers.parseEther("0.5"));
  assert.equal(challengerStakeAfter, challengerStakeBefore - ethers.parseEther("0.5"));
  assert.equal(challengerBondAfterResolution.lockedChallengeBondWei, 0n);
  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      2,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|reverted/
  );
  await advanceTime(provider, PAST_WINDOW_SECONDS);
  await (await game.finalizeUnchallenged(taskId, { gasLimit: 1_000_000 })).wait();
  const finalTask = await game.getTaskStatus(taskId);
  assert.equal(Number(finalTask.decision), 1, "accepted once no live challenge remains");
  assert.equal(Number(finalTask.status), 3);
});

test("supporting and dissenting auditors can keep bisection moving if the operator or original challenger disappear", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("auditor-defenders");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-defenders")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengerSideDefender = leafAuditors[1];
  const operatorSideDefender = assignedAuditors.find(
    (auditor) => !leafAuditors.some((leafAuditor) => leafAuditor.address === auditor.address)
  );
  const operatorSideDefenderLeaf = await firstAssignedLeaf(
    game,
    taskId,
    operatorSideDefender,
    leaves.length,
    0
  );
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address === operatorSideDefender.address;
    const podRoot =
      auditor.address === challenger.address
        ? challengeTranscript.root
        : ethers.keccak256(
            ethers.toUtf8Bytes(`pod:${auditor.address}:supports=${supportsOperator}`)
          );
    const auditedLeafIndex =
      auditor.address === operatorSideDefender.address ? operatorSideDefenderLeaf : leafHint;
    auditCommitments.push(
      await commitAudit(game, taskId, auditor, supportsOperator, podRoot, auditedLeafIndex)
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  await bisectAndResolve(
    game,
    taskId,
    operatorSideDefender,
    challengerSideDefender,
    operatorTree,
    challengerTree,
    badLeaf,
    leaves[2]
  );

  const task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.decision), 2);
  assert.equal(Number(task.status), 3);
});

test("refundable dispute bonds cap concurrent challenge spam", async () => {
  // Three concurrent tasks: see deployFixture's windowSeconds note.
  const { provider, game, operator, auditors, decryptors } = await deployFixture({
    windowSeconds: HEAVY_WINDOW_SECONDS
  });
  const goodTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const badOperatorTree = buildMerkleTree(operatorLeaves);
  const taskIds = [
    ethers.encodeBytes32String("spam-1"),
    ethers.encodeBytes32String("spam-2"),
    ethers.encodeBytes32String("spam-3")
  ];

  for (const taskId of taskIds) {
    await (
      await game
        .connect(operator)
        .createTask(...boundCreateTaskArgs(taskId, badOperatorTree, operatorLeaves, ethers.id(`result:${taskId}`)))
    ).wait();
    await sampleTaskParticipants(game, taskId);
  }

  const assignedAuditorsByTask = [];
  const assignedDecryptorsByTask = [];
  for (const taskId of taskIds) {
    assignedAuditorsByTask.push(await assignedWallets(game, taskId, auditors, "getAssignedAuditors"));
    assignedDecryptorsByTask.push(
      await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors")
    );
  }

  const challenger = assignedAuditorsByTask[0][0];
  const challengeLeafByTask = [];
  const transcripts = [];
  for (const taskId of taskIds) {
    const leafIndex = await firstAssignedLeaf(game, taskId, challenger, leaves.length, 2);
    challengeLeafByTask.push(leafIndex);
    transcripts.push(
      buildChallengeAuditTranscript(
        taskId,
        challenger,
        badOperatorTree.root,
        leafIndex,
        operatorLeaves[leafIndex],
        leaves[leafIndex]
      )
    );
  }

  for (let taskIndex = 0; taskIndex < taskIds.length; taskIndex += 1) {
    const taskId = taskIds[taskIndex];
    const assignedAuditors = assignedAuditorsByTask[taskIndex];
    const transcript = transcripts[taskIndex];
    for (const auditor of assignedAuditors) {
      const supportsOperator = auditor.address !== challenger.address;
      const podRoot = supportsOperator
        ? ethers.keccak256(
            ethers.toUtf8Bytes(`pod:${taskId}:${auditor.address}:supports=${supportsOperator}`)
          )
        : transcript.root;
      const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
        taskId,
        auditor.address,
        challengeLeafByTask[taskIndex]
      );
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        auditorCoversChallengedLeaf ? challengeLeafByTask[taskIndex] : undefined
      );
    }
  }

  // These three tasks are created one after another, so on a real chain each
  // carries deadlines later than the previous by however long the creation and
  // sampling transactions took. There is then NO single instant that lies
  // inside every task's opening window at once: waiting for the first task's
  // commit deadline leaves the later tasks still committing, and waiting for
  // the last one's overshoots the first task's opening deadline, so its
  // openVerdict reverts. Both were observed on the QBFT network.
  //
  // The schedule that satisfies all three is per task, in creation order. The
  // waits stay monotonic because the deadlines do, so no task is ever waited
  // backwards.
  for (let taskIndex = 0; taskIndex < taskIds.length; taskIndex += 1) {
    await advanceToRevealWindow(provider, game, taskIds[taskIndex]);
    const assignedAuditors = assignedAuditorsByTask[taskIndex];
    const assignedDecryptors = assignedDecryptorsByTask[taskIndex];
    const transcript = transcripts[taskIndex];
    for (let auditorIndex = 0; auditorIndex < assignedAuditors.length; auditorIndex += 1) {
      const auditor = assignedAuditors[auditorIndex];
      const supportsOperator = auditor.address !== challenger.address;
      const podRoot = supportsOperator
        ? ethers.keccak256(
            ethers.toUtf8Bytes(
              `pod:${taskIds[taskIndex]}:${auditor.address}:supports=${supportsOperator}`
            )
          )
        : transcript.root;
      await openCommittedAudit(
        game,
        taskIds[taskIndex],
        auditor,
        {
          verdict: supportsOperator,
          salt: ethers.keccak256(
            ethers.toUtf8Bytes(
              `${taskIds[taskIndex]}:${auditor.address}:${supportsOperator}:${podRoot}`
            )
          ),
          podRoot
        },
        assignedDecryptors.slice(0, 2)
      );
    }
  }

  // Per task again, and for the same reason: each challenge has to be opened
  // inside its own task's challenge window.
  for (let taskIndex = 0; taskIndex < 2; taskIndex += 1) {
    await advancePastOpenWindow(provider, game, taskIds[taskIndex]);
    const transcript = transcripts[taskIndex];
    await proveDiligence(game, taskIds[taskIndex], challenger, transcript);
    await (
      await game.connect(challenger).openChallenge(
        taskIds[taskIndex],
        goodTree.root,
        challengeLeafByTask[taskIndex],
        transcript.errorDigest,
        transcript.leaves[0],
        transcript.proof,
        transcript.proofSiblingOnLeft
      )
    ).wait();
  }

  // Per-task bond for a 4-leaf trace: base + rounds x per-round, floored at
  // the slash amount (0.5 ETH); two open challenges lock twice that.
  const requiredBond = ethers.parseEther("0.5");
  const challengerBreakdown = await game.getParticipantStakeBreakdown(challenger.address);
  assert.equal(challengerBreakdown.lockedChallengeBondWei, requiredBond * 2n);
  assert.equal(challengerBreakdown.availableStakeWei, 0n);

  const blockedTranscript = transcripts[2];
  await proveDiligence(game, taskIds[2], challenger, blockedTranscript);
  await assert.rejects(
    game.connect(challenger).openChallenge(
      taskIds[2],
      goodTree.root,
      challengeLeafByTask[2],
      blockedTranscript.errorDigest,
      blockedTranscript.leaves[0],
      blockedTranscript.proof,
      blockedTranscript.proofSiblingOnLeft
    ),
    /CALL_EXCEPTION|transaction execution reverted|challenge bond unavailable/
  );
});

test("local FHEVM runtime resolves the disputed micro-instruction on-chain", async () => {
  const {
    provider,
    game,
    operator,
    auditors,
    decryptors,
    localFhevm
  } = await deployFixture({ withLocalFhevm: true });
  const { executor, fhevmVerifier } = localFhevm;
  const fhevmVerifierAddress = await fhevmVerifier.getAddress();
  await expectCallException(
    () => game.setFhevmVerifier(fhevmVerifierAddress),
    /CALL_EXCEPTION/
  );

  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("fhevm-leaf");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-fhevm")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const wrongAuditor = leafAuditors.find((auditor) => auditor.address !== challenger.address);
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const auditorCoversChallengedLeaf = await game.isAuditorAssignedToLeaf(
      taskId,
      auditor.address,
      leafHint
    );
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:fhevm=${supportsOperator}`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        auditorCoversChallengedLeaf ? leafHint : undefined
      )
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }

  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  await bisectToLeaf(game, taskId, operator, challenger, operatorTree, challengerTree);

  await expectCallException(
    () => game.resolveLeafDispute(taskId, traceLeafClaim(badLeaf), traceLeafClaim(leaves[2])),
    /CALL_EXCEPTION/
  );

  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  const wrongAuditorStakeBefore = await game.getParticipantStake(wrongAuditor.address);
  await (
    await game.connect(challenger).requestFhevmLeafResolution(
      taskId,
      traceLeafClaim(badLeaf),
      traceLeafClaim(leaves[2]),
      {
        lhsInputProof: "0x01",
        rhsInputProof: "0x01",
        operatorClaimedProof: "0x01",
        challengerClaimedProof: "0x01"
      }
    )
  ).wait();

  const pending = await game.getPendingFhevmLeafResolution(taskId);
  assert.equal(pending.active, true);
  assert.equal(pending.verifier, await fhevmVerifier.getAddress());
  assert.equal(Number(pending.leafIndex), leafHint);

  const operatorValid = (await executor.plaintextOf(pending.operatorValidHandle)) !== 0n;
  const challengerValid = (await executor.plaintextOf(pending.challengerValidHandle)) !== 0n;
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

  const task = await game.getTaskStatus(taskId);
  const operatorStakeAfter = await game.getParticipantStake(operator.address);
  const challengerStakeAfter = await game.getParticipantStake(challenger.address);
  const wrongAuditorStakeAfter = await game.getParticipantStake(wrongAuditor.address);
  const wrongAuditRecord = await game.getAuditStatus(taskId, wrongAuditor.address);

  assert.equal(Number(task.decision), 2);
  assert.equal(Number(task.status), 3);
  assert.equal(operatorStakeAfter, operatorStakeBefore - ethers.parseEther("0.5"));
  assert.equal(wrongAuditorStakeAfter, wrongAuditorStakeBefore - ethers.parseEther("0.5"));
  assert.equal(challengerStakeAfter, challengerStakeBefore + ethers.parseEther("1.0"));
  assert.equal(wrongAuditRecord.wrongVerdictSlashed, true);
});

// The route a dispute over REAL ciphertext handles takes. The equality bit is
// decided off-chain by comparing handles and settled on-chain from t+1 EIP-712
// core signatures; no operand value crosses the ABI at any point. See
// VerifiableFHEDisputeGame.settleLeafViaAttestedDecision.
test("attested leaf decision: t+1 signatures settle the leaf, fewer or misbound do not", async () => {
  const { artifacts, provider, deployer, game, operator, auditors, decryptors } =
    await deployFixture();

  // Four deterministic "KMS core" identities, n=4, t=1 => threshold 2 = t+1.
  const cores = Array.from({ length: 4 }, (_, index) =>
    new ethers.Wallet(ethers.keccak256(ethers.toUtf8Bytes(`test-leaf-core:${index}`)))
  );
  const attestor = await new ethers.ContractFactory(
    artifacts.ZamaKMSVerdictVerifier.abi,
    artifacts.ZamaKMSVerdictVerifier.bytecode,
    deployer
  ).deploy("VCFHE-Leaf-Decision", "1", 0, ethers.ZeroAddress, cores.map((c) => c.address), 2);
  await attestor.waitForDeployment();
  const attestorAddress = await attestor.getAddress();
  // The EIP-712 domain the cores sign, and the chain id the contract reads from
  // `block.chainid`, must both be the id of the chain this suite is running
  // against. Reading it from the provider is what lets this test run on the
  // QBFT network as well as in process.
  const attestedChainId = await currentChainId(provider);
  await (await game.setLeafDecisionVerifier(attestorAddress)).wait();
  // One-time wiring.
  await expectCallException(
    () => game.setLeafDecisionVerifier(attestorAddress),
    /CALL_EXCEPTION/
  );

  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("attested-leaf");

  await (
    await game
      .connect(operator)
      .createTask(
        ...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-attested"))
      )
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const covers = await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafHint);
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:attested`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(
        game,
        taskId,
        auditor,
        supportsOperator,
        podRoot,
        covers ? leafHint : undefined
      )
    );
  }
  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();
  await bisectToLeaf(game, taskId, operator, challenger, operatorTree, challengerTree);

  const operatorClaim = traceLeafClaim(badLeaf);
  const challengerClaim = traceLeafClaim(leaves[2]);
  const domain = {
    name: "VCFHE-Leaf-Decision",
    version: "1",
    chainId: attestedChainId,
    verifyingContract: attestorAddress
  };
  const types = {
    PublicDecryptVerification: [
      { name: "ctHandles", type: "bytes32[]" },
      { name: "decryptedResult", type: "bytes" },
      { name: "extraData", type: "bytes" }
    ]
  };
  const decryptedResult = ethers.AbiCoder.defaultAbiCoder().encode(
    ["bool", "bool"],
    [false, true]
  );
  const ctHandles = [operatorClaim.claimedHandle, challengerClaim.claimedHandle];
  const binding = await game.leafDecisionBinding(taskId, leafHint, badLeaf.opcode);
  // The binding is exactly what the contract says it is.
  assert.equal(
    binding,
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint256", "bytes32", "uint32", "uint8"],
      [
        await game.FHE_POD_LEAF_DECISION_V1(),
        await game.getAddress(),
        attestedChainId,
        taskId,
        leafHint,
        badLeaf.opcode
      ]
    )
  );
  // The on-chain digest matches ethers' EIP-712 encoding of the KMS struct.
  assert.equal(
    await attestor.publicDecryptionDigest(ctHandles, decryptedResult, binding),
    ethers.TypedDataEncoder.hash(domain, types, {
      ctHandles,
      decryptedResult,
      extraData: binding
    })
  );

  const sign = async (count, extraData) => {
    const signatures = [];
    for (const core of cores.slice(0, count)) {
      signatures.push(
        await core.signTypedData(domain, types, {
          ctHandles,
          decryptedResult,
          extraData
        })
      );
    }
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes[]", "bytes"],
      [signatures, extraData]
    );
  };

  // t signatures are not enough.
  const singleSignature = await sign(1, binding);
  await expectCallException(
    () =>
      game
        .connect(challenger)
        .settleLeafViaAttestedDecision(
          taskId,
          operatorClaim,
          challengerClaim,
          false,
          true,
          singleSignature
        ),
    /CALL_EXCEPTION/
  );
  // A bundle bound to a DIFFERENT leaf cannot settle this one, even with t+1
  // valid signatures over its own digest.
  const foreignBinding = await game.leafDecisionBinding(taskId, leafHint + 1, badLeaf.opcode);
  const misboundProof = await sign(2, foreignBinding);
  await expectCallException(
    () =>
      game
        .connect(challenger)
        .settleLeafViaAttestedDecision(
          taskId,
          operatorClaim,
          challengerClaim,
          false,
          true,
          misboundProof
        ),
    /CALL_EXCEPTION/
  );

  const boundProof = await sign(2, binding);
  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  const receipt = await (
    await game
      .connect(challenger)
      .settleLeafViaAttestedDecision(
        taskId,
        operatorClaim,
        challengerClaim,
        false,
        true,
        boundProof
      )
  ).wait();

  // Settlement is attributed to the attestor, not to a micro-verifier.
  const checked = receipt.logs
    .map((log) => {
      try {
        return game.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((event) => event?.name === "LeafCheckedOnChain");
  assert.ok(checked, "LeafCheckedOnChain must be emitted");
  assert.equal(Number(checked.args.leafIndex), leafHint);
  assert.equal(checked.args.operatorValid, false);
  assert.equal(checked.args.challengerValid, true);
  assert.equal(ethers.getAddress(checked.args.verifier), attestorAddress);

  const task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.decision), 2);
  assert.equal(Number(task.status), 3);
  assert.equal(
    await game.getParticipantStake(operator.address),
    operatorStakeBefore - ethers.parseEther("0.5")
  );
  assert.equal(
    await game.getParticipantStake(challenger.address),
    challengerStakeBefore + ethers.parseEther("1.0")
  );
});

// Value-equal, byte-different claims. tfhe-rs does not serialize a correct
// result identically across evaluation schedules, so a challenger that
// commits its OWN re-evaluation (or deliberately re-encrypts the operator's
// value) isolates a leaf at which BOTH claims validate. The operator's claim is
// correct, so the challenge is unsupported and settles against the challenger.
// Before this rule the contract reverted on (true,true), the terminal round
// produced no decision, and `timeoutDispute` slashed the honest operator.
test("attested leaf decision: value-equal byte-different claims settle against the challenger", async () => {
  const { artifacts, provider, deployer, game, operator, auditors, decryptors } =
    await deployFixture();

  const cores = Array.from({ length: 4 }, (_, index) =>
    new ethers.Wallet(ethers.keccak256(ethers.toUtf8Bytes(`test-leaf-core-eq:${index}`)))
  );
  const attestor = await new ethers.ContractFactory(
    artifacts.ZamaKMSVerdictVerifier.abi,
    artifacts.ZamaKMSVerdictVerifier.bytecode,
    deployer
  ).deploy("VCFHE-Leaf-Decision", "1", 0, ethers.ZeroAddress, cores.map((c) => c.address), 2);
  await attestor.waitForDeployment();
  const attestorAddress = await attestor.getAddress();
  const attestedChainId = await currentChainId(provider);
  await (await game.setLeafDecisionVerifier(attestorAddress)).wait();

  // Honest operator: the committed trace is the reference trace.
  const operatorTree = buildMerkleTree(leaves);
  // The challenger's leaf 2 decrypts to the same value as the operator's but
  // is a different ciphertext, hence a different handle.
  const leafHint = 2;
  const reencryptedLeaf = mutateLeafClaim(leaves[leafHint], {
    claimedHandle: ethers.keccak256(ethers.toUtf8Bytes("re-encryption of the same value"))
  });
  const challengerLeaves = [...leaves];
  challengerLeaves[leafHint] = reencryptedLeaf;
  const challengerTree = buildMerkleTree(challengerLeaves);
  const taskId = ethers.encodeBytes32String("attested-leaf-eq");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, leaves, ethers.id("result-attested-eq")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors");
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    leaves[leafHint],
    reencryptedLeaf
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const covers = await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafHint);
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:attested-eq`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(game, taskId, auditor, supportsOperator, podRoot, covers ? leafHint : undefined)
    );
  }
  await advanceToRevealWindow(provider, game, taskId);
  for (let index = 0; index < assignedAuditors.length; index += 1) {
    await openCommittedAudit(
      game,
      taskId,
      assignedAuditors[index],
      auditCommitments[index],
      assignedDecryptors.slice(0, 2)
    );
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengeTranscript.errorDigest,
      challengeTranscript.leaves[0],
      challengeTranscript.proof,
      challengeTranscript.proofSiblingOnLeft
    )
  ).wait();
  await bisectToLeaf(game, taskId, operator, challenger, operatorTree, challengerTree);

  const operatorClaim = traceLeafClaim(leaves[leafHint]);
  const challengerClaim = traceLeafClaim(reencryptedLeaf);
  assert.notEqual(operatorClaim.claimedHandle, challengerClaim.claimedHandle);
  const domain = {
    name: "VCFHE-Leaf-Decision",
    version: "1",
    chainId: attestedChainId,
    verifyingContract: attestorAddress
  };
  const types = {
    PublicDecryptVerification: [
      { name: "ctHandles", type: "bytes32[]" },
      { name: "decryptedResult", type: "bytes" },
      { name: "extraData", type: "bytes" }
    ]
  };
  // Both recomputations decrypt equal to their claims: (true, true).
  const decryptedResult = ethers.AbiCoder.defaultAbiCoder().encode(["bool", "bool"], [true, true]);
  const ctHandles = [operatorClaim.claimedHandle, challengerClaim.claimedHandle];
  const binding = await game.leafDecisionBinding(taskId, leafHint, leaves[leafHint].opcode);
  const signatures = [];
  for (const core of cores.slice(0, 2)) {
    signatures.push(
      await core.signTypedData(domain, types, { ctHandles, decryptedResult, extraData: binding })
    );
  }
  const boundProof = ethers.AbiCoder.defaultAbiCoder().encode(["bytes[]", "bytes"], [signatures, binding]);

  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  // Resolution is permissionless; the honest operator triggers it here.
  const receipt = await (
    await game
      .connect(operator)
      .settleLeafViaAttestedDecision(taskId, operatorClaim, challengerClaim, true, true, boundProof)
  ).wait();

  const checked = receipt.logs
    .map((log) => {
      try {
        return game.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((event) => event?.name === "LeafCheckedOnChain");
  assert.ok(checked, "LeafCheckedOnChain must be emitted for the (true,true) leaf");
  assert.equal(Number(checked.args.leafIndex), leafHint);
  assert.equal(checked.args.operatorValid, true);
  assert.equal(checked.args.challengerValid, true);

  const task = await game.getTaskStatus(taskId);
  assert.equal(Number(task.status), 1, "the task returns to Auditing after a lost challenge");
  assert.equal(task.challengeTriggered, false);
  assert.equal(
    await game.getParticipantStake(operator.address),
    operatorStakeBefore + ethers.parseEther("0.5"),
    "the honest operator keeps its stake and receives the challenge bond"
  );
  assert.equal(
    await game.getParticipantStake(challenger.address),
    challengerStakeBefore - ethers.parseEther("0.5"),
    "the challenger forfeits its bond"
  );
  // No default judgment can follow a decided leaf.
  await expectCallException(() => game.timeoutDispute(taskId), /CALL_EXCEPTION/);
  await advanceTime(provider, PAST_WINDOW_SECONDS);
  await (await game.finalizeUnchallenged(taskId, { gasLimit: 1_000_000 })).wait();
  assert.equal(Number((await game.getTaskStatus(taskId)).decision), 1, "accepted: no live challenge");
});

test("lazy auditor can be slashed and a single decryptor cannot open a verdict alone", async () => {
  const { provider, game, operator, auditors, decryptors, reporter } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("lazy");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, ethers.id("result-lazy")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );

  const activeAuditor = assignedAuditors[0];
  const lazyAuditor = assignedAuditors[1];
  const auditCommitment = await commitAudit(
    game,
    taskId,
    activeAuditor,
    true,
    ethers.keccak256(ethers.toUtf8Bytes(`pod:${activeAuditor.address}:lazy`))
  );

  await advanceToRevealWindow(provider, game, taskId);
  await (
    await game
      .connect(assignedDecryptors[0])
      .openVerdict(
        taskId,
        activeAuditor.address,
        auditCommitment.verdict,
        auditCommitment.salt,
        auditCommitment.podRoot
      )
  ).wait();

  let auditRecord = await game.getAuditStatus(taskId, activeAuditor.address);
  assert.equal(auditRecord.opened, false);

  await (
    await game
      .connect(assignedDecryptors[1])
      .openVerdict(
        taskId,
        activeAuditor.address,
        auditCommitment.verdict,
        auditCommitment.salt,
        auditCommitment.podRoot
      )
  ).wait();
  auditRecord = await game.getAuditStatus(taskId, activeAuditor.address);
  assert.equal(auditRecord.opened, true);

  const lazyStakeBefore = await game.getParticipantStake(lazyAuditor.address);
  const reporterStakeBefore = await game.getParticipantStake(reporter.address);

  await advancePastOpenWindow(provider, game, taskId);
  await (await game.connect(reporter).slashLazyAuditor(taskId, lazyAuditor.address)).wait();

  const lazyStakeAfter = await game.getParticipantStake(lazyAuditor.address);
  const reporterStakeAfter = await game.getParticipantStake(reporter.address);

  assert.equal(lazyStakeAfter, lazyStakeBefore - ethers.parseEther("0.5"));
  assert.equal(reporterStakeAfter, reporterStakeBefore + ethers.parseEther("0.5"));
});

test("diligence reward on the optimistic path requires sampled precommitted evidence", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("reward-ok");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, ethers.id("result-reward-ok")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const [auditor] = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const auditedLeafIndex = await firstAssignedLeaf(game, taskId, auditor);
  const transcript = buildChallengeAuditTranscript(
    taskId,
    auditor,
    tree.root,
    auditedLeafIndex,
    leaves[auditedLeafIndex],
    leaves[auditedLeafIndex]
  );
  const auditCommitment = await commitAudit(
    game,
    taskId,
    auditor,
    true,
    transcript.root,
    auditedLeafIndex
  );
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(game, taskId, auditor, auditCommitment, assignedDecryptors.slice(0, 2));
  await advancePastOpenWindow(provider, game, taskId);
  await sealDiligenceRandomness(game, taskId);
  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(taskId)).wait();

  const stakeBeforeClaim = await game.getParticipantStake(auditor.address);
  const reward = await game.DILIGENCE_REWARD_WEI();
  await claimDiligenceRewardWithSealedSeed(game, taskId, auditor, transcript);
  const stakeAfterClaim = await game.getParticipantStake(auditor.address);

  assert.equal(stakeAfterClaim, stakeBeforeClaim + reward);
  await expectCallException(
    () => claimDiligenceRewardWithSealedSeed(game, taskId, auditor, transcript),
    /CALL_EXCEPTION|transaction execution reverted|diligence reward claimed/
  );
});

test("documents that an arbitrary precommitted checkpoint tree can earn an optimistic reward", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("reward-arbitrary");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, leaves, ethers.id("result-arbitrary")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const [auditor] = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const auditedLeafIndex = await firstAssignedLeaf(game, taskId, auditor);
  const arbitraryOperatorLeaf = { opcode: 14, lhs: 111, rhs: 222, claimed: 333 };
  const arbitraryRecomputedLeaf = { opcode: 13, lhs: 444, rhs: 555, claimed: 666 };
  const arbitraryAuditLeaf = {
    leafIndex: auditedLeafIndex,
    operatorLeafHash: leafHash(arbitraryOperatorLeaf),
    recomputedLeafHash: leafHash(arbitraryRecomputedLeaf),
    errorDigest: ethers.id("arbitrary-audit-error")
  };
  const arbitraryTranscript = buildAuditTranscript({
    taskId,
    auditorAddress: auditor.address,
    operatorTraceRoot: tree.root,
    auditTraceLeaf: arbitraryAuditLeaf,
    operatorLeaf: arbitraryOperatorLeaf,
    recomputedLeaf: arbitraryRecomputedLeaf
  });
  const auditCommitment = await commitAudit(
    game,
    taskId,
    auditor,
    true,
    arbitraryTranscript.root,
    auditedLeafIndex
  );
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    auditor,
    auditCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await sealDiligenceRandomness(game, taskId);
  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(taskId)).wait();

  const stakeBeforeClaim = await game.getParticipantStake(auditor.address);
  const reward = await game.DILIGENCE_REWARD_WEI();
  await claimDiligenceRewardWithSealedSeed(
    game,
    taskId,
    auditor,
    arbitraryTranscript
  );
  const stakeAfterClaim = await game.getParticipantStake(auditor.address);
  assert.equal(stakeAfterClaim, stakeBeforeClaim + reward);
});

test("diligence reward rejects unopened or opaque lazy audit commitments", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const unopenedTaskId = ethers.encodeBytes32String("reward-unopened");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(unopenedTaskId, tree, leaves, ethers.id("result-unopened")))
  ).wait();
  await sampleTaskParticipants(game, unopenedTaskId);

  const [unopenedAuditor] = await assignedWallets(
    game,
    unopenedTaskId,
    auditors,
    "getAssignedAuditors"
  );
  const unopenedLeafIndex = await firstAssignedLeaf(game, unopenedTaskId, unopenedAuditor);
  const unopenedTranscript = buildChallengeAuditTranscript(
    unopenedTaskId,
    unopenedAuditor,
    tree.root,
    unopenedLeafIndex,
    leaves[unopenedLeafIndex],
    leaves[unopenedLeafIndex]
  );
  await commitAudit(
    game,
    unopenedTaskId,
    unopenedAuditor,
    true,
    unopenedTranscript.root,
    unopenedLeafIndex
  );
  await advanceToRevealWindow(provider, game, unopenedTaskId);
  await advancePastOpenWindow(provider, game, unopenedTaskId);
  await sealDiligenceRandomness(game, unopenedTaskId);
  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(unopenedTaskId)).wait();

  await expectCallException(
    () =>
      claimDiligenceRewardWithSealedSeed(
        game,
        unopenedTaskId,
        unopenedAuditor,
        unopenedTranscript
      ),
    /CALL_EXCEPTION|transaction execution reverted|verdict not opened/
  );

  const opaqueTaskId = ethers.encodeBytes32String("reward-opaque");
  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(opaqueTaskId, tree, leaves, ethers.id("result-opaque")))
  ).wait();
  await sampleTaskParticipants(game, opaqueTaskId);

  const [opaqueAuditor] = await assignedWallets(
    game,
    opaqueTaskId,
    auditors,
    "getAssignedAuditors"
  );
  const opaqueLeafIndex = await firstAssignedLeaf(game, opaqueTaskId, opaqueAuditor);
  const opaqueTranscript = buildChallengeAuditTranscript(
    opaqueTaskId,
    opaqueAuditor,
    tree.root,
    opaqueLeafIndex,
    leaves[opaqueLeafIndex],
    leaves[opaqueLeafIndex]
  );
  const opaqueCommitment = await commitAudit(
    game,
    opaqueTaskId,
    opaqueAuditor,
    true,
    ethers.keccak256(ethers.toUtf8Bytes("opaque-lazy-pod-root")),
    opaqueLeafIndex
  );
  const assignedDecryptors = await assignedWallets(
    game,
    opaqueTaskId,
    decryptors,
    "getAssignedDecryptors"
  );

  await advanceToRevealWindow(provider, game, opaqueTaskId);
  await openCommittedAudit(
    game,
    opaqueTaskId,
    opaqueAuditor,
    opaqueCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, opaqueTaskId);
  await sealDiligenceRandomness(game, opaqueTaskId);
  await advancePastChallengeWindow(provider);
  await (await game.finalizeUnchallenged(opaqueTaskId)).wait();

  await expectCallException(
    () => claimDiligenceRewardWithSealedSeed(game, opaqueTaskId, opaqueAuditor, opaqueTranscript),
    /CALL_EXCEPTION|transaction execution reverted|bad diligence proof/
  );
});

test("same-stage secondary auditor reward requires own evidence and correct objective verdict", async () => {
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const leafHint = 2;
  const badLeaf = mutateLeafClaim(leaves[leafHint], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[leafHint] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const challengerTree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("reward-stage");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-reward-stage")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const [challenger, secondaryAuditor] = await assignedWalletsForLeaf(
    game,
    taskId,
    leafHint,
    auditors
  );
  const assignedDecryptors = await assignedWallets(
    game,
    taskId,
    decryptors,
    "getAssignedDecryptors"
  );
  const challengerTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );
  const secondaryTranscript = buildChallengeAuditTranscript(
    taskId,
    secondaryAuditor,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[leafHint]
  );
  const challengerCommitment = await commitAudit(
    game,
    taskId,
    challenger,
    false,
    challengerTranscript.root,
    leafHint
  );
  const secondaryCommitment = await commitAudit(
    game,
    taskId,
    secondaryAuditor,
    false,
    secondaryTranscript.root,
    leafHint
  );

  await advanceToRevealWindow(provider, game, taskId);
  await openCommittedAudit(
    game,
    taskId,
    challenger,
    challengerCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await openCommittedAudit(
    game,
    taskId,
    secondaryAuditor,
    secondaryCommitment,
    assignedDecryptors.slice(0, 2)
  );
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengerTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId,
      challengerTree.root,
      leafHint,
      challengerTranscript.errorDigest,
      challengerTranscript.leaves[0],
      challengerTranscript.proof,
      challengerTranscript.proofSiblingOnLeft
    )
  ).wait();
  await bisectAndResolve(
    game,
    taskId,
    operator,
    challenger,
    operatorTree,
    challengerTree,
    badLeaf,
    leaves[leafHint]
  );

  const copiedCheckpointIndex = await game.getRequiredDiligenceCheckpointIndex(
    taskId,
    secondaryAuditor.address
  );
  const copiedSelected = selectAuditDiligenceCheckpoint(
    challengerTranscript,
    copiedCheckpointIndex
  );
  await expectCallException(
    () =>
      game.connect(secondaryAuditor).claimDiligenceReward(
        taskId,
        copiedSelected.diligenceCheckpoint,
        copiedSelected.diligenceProof,
        copiedSelected.diligenceProofSiblingOnLeft
      ),
    /CALL_EXCEPTION|transaction execution reverted|bad diligence proof/
  );

  const stakeBeforeClaim = await game.getParticipantStake(secondaryAuditor.address);
  const reward = await game.DILIGENCE_REWARD_WEI();
  await claimDiligenceRewardWithSealedSeed(
    game,
    taskId,
    secondaryAuditor,
    secondaryTranscript
  );
  const stakeAfterClaim = await game.getParticipantStake(secondaryAuditor.address);

  assert.equal(stakeAfterClaim, stakeBeforeClaim + reward);
});

test("objective verifier supports expanded micro-operation surface", async () => {
  const { verifier } = await deployFixture();
  const cases = [
    { name: "MUL", opcode: 1, lhs: 12, rhs: 5, claimed: 60 },
    { name: "SHR", opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
    { name: "CAST_U8", opcode: 3, lhs: 257, rhs: 0, claimed: 1 },
    { name: "MIN", opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
    { name: "BITAND", opcode: 5, lhs: 7, rhs: 1, claimed: 1 },
    { name: "ADD", opcode: 6, lhs: 10, rhs: 4, claimed: 14 },
    { name: "SUB", opcode: 7, lhs: 10, rhs: 4, claimed: 6 },
    { name: "DIV", opcode: 8, lhs: 20, rhs: 4, claimed: 5 },
    { name: "MOD", opcode: 9, lhs: 22, rhs: 5, claimed: 2 },
    { name: "EQ", opcode: 10, lhs: 9, rhs: 9, claimed: 1 },
    { name: "LT", opcode: 11, lhs: 8, rhs: 9, claimed: 1 },
    { name: "GT", opcode: 12, lhs: 10, rhs: 9, claimed: 1 },
    { name: "BITOR", opcode: 13, lhs: 4, rhs: 1, claimed: 5 },
    { name: "BITXOR", opcode: 14, lhs: 7, rhs: 3, claimed: 4 },
    { name: "ADD_CHAIN", opcode: 15, lhs: 10, rhs: 8, claimed: 18 }
  ];

  for (const item of cases) {
    assert.equal(
      await verifier.verifyLeaf(item.opcode, item.lhs, item.rhs, item.claimed),
      true,
      `${item.name} should verify`
    );
    assert.equal(
      await verifier.verifyLeaf(item.opcode, item.lhs, item.rhs, item.claimed + 1),
      false,
      `${item.name} should reject a wrong claim`
    );
  }

  assert.equal(await verifier.verifyLeaf(8, 20, 0, 0), false);
  assert.equal(await verifier.verifyLeaf(9, 20, 0, 0), false);
});

test("lazy trace-mirroring auditor supporting a corrupted stage is slashed and denied reward", async () => {
  // A "mirror" auditor copies the operator's published trace instead of
  // recomputing: it commits to the operator's claimed values and votes to
  // support the operator. On a corrupted, successfully challenged stage this
  // mirror is objectively wrong. The test asserts the two ex-post defenses the
  // experiment claims: (1) the mirror is wrong-verdict slashed once the objective
  // leaf resolution proves the stage wrong, and (2) it can no longer collect a
  // diligence reward. This bounds the residual lazy-auditor gap: mirroring is
  // deterred economically, not prevented cryptographically.
  const { provider, game, operator, auditors, decryptors } = await deployFixture();
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("mirror-lazy");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-mirror")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors");
  const leafHint = 2;
  const stageAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = stageAuditors[0];
  const mirror = stageAuditors[1]; // copies the operator trace, supports operator

  const challengeTranscript = buildChallengeAuditTranscript(
    taskId,
    challenger,
    operatorTree.root,
    leafHint,
    badLeaf,
    leaves[2]
  );
  // The mirror's PoD root mirrors the operator's *claimed* (corrupted) leaf: it
  // is internally consistent (so diligence would pass on an honest task) but it
  // supports the wrong value here.
  const mirrorTranscript = buildChallengeAuditTranscript(
    taskId,
    mirror,
    operatorTree.root,
    leafHint,
    badLeaf,
    badLeaf
  );

  const commitments = {};
  for (const auditor of assignedAuditors) {
    const isChallenger = auditor.address === challenger.address;
    const isMirror = auditor.address === mirror.address;
    const auditedLeafIndex =
      isChallenger || isMirror
        ? leafHint
        : await firstAssignedLeaf(game, taskId, auditor, leaves.length, 0);
    const podRoot = isChallenger
      ? challengeTranscript.root
      : isMirror
        ? mirrorTranscript.root
        : ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}:stage=${auditedLeafIndex}`));
    commitments[auditor.address] = await commitAudit(
      game,
      taskId,
      auditor,
      !isChallenger, // challenger dissents; everyone else (incl. mirror) supports
      podRoot,
      auditedLeafIndex
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (const auditor of assignedAuditors) {
    await openCommittedAudit(game, taskId, auditor, commitments[auditor.address], assignedDecryptors.slice(0, 2));
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game
      .connect(challenger)
      .openChallenge(
        taskId,
        challengerTree.root,
        leafHint,
        challengeTranscript.errorDigest,
        challengeTranscript.leaves[0],
        challengeTranscript.proof,
        challengeTranscript.proofSiblingOnLeft
      )
  ).wait();

  const mirrorStakeBefore = await game.getParticipantStake(mirror.address);
  await bisectAndResolve(game, taskId, operator, challenger, operatorTree, challengerTree, badLeaf, leaves[2]);
  const mirrorStakeAfter = await game.getParticipantStake(mirror.address);
  const mirrorRecord = await game.getAuditStatus(taskId, mirror.address);

  // (1) ex-post slash: the mirror lost its stake for supporting the wrong stage.
  assert.equal(mirrorRecord.wrongVerdictSlashed, true);
  assert.equal(mirrorStakeAfter, mirrorStakeBefore - ethers.parseEther("0.5"));

  // (2) reward denial: a slashed auditor cannot claim a diligence reward.
  await expectCallException(
    () => claimDiligenceRewardWithSealedSeed(game, taskId, mirror, mirrorTranscript),
    /CALL_EXCEPTION|transaction execution reverted|auditor verdict slashed|task not finalized/
  );
});

// Drives a corrupted task through audit, diligence, and openChallenge so that
// the task is in the Challenged phase with the dispute still above the leaf
// stage. Returns the context needed to exercise a bisection stall.
async function driveToChallenged(ctx) {
  const { provider, game, operator, auditors, decryptors } = ctx;
  const challengerTree = buildMerkleTree(leaves);
  const badLeaf = mutateLeafClaim(leaves[2], { claimed: 8 });
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = badLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String(ctx.label);

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id(ctx.label)))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors");
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId, challenger, operatorTree.root, leafHint, badLeaf, leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const covers = await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafHint);
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(game, taskId, auditor, supportsOperator, podRoot, covers ? leafHint : undefined)
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let i = 0; i < assignedAuditors.length; i += 1) {
    await openCommittedAudit(game, taskId, assignedAuditors[i], auditCommitments[i], assignedDecryptors.slice(0, 2));
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId, challengerTree.root, leafHint, challengeTranscript.errorDigest,
      challengeTranscript.leaves[0], challengeTranscript.proof, challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  return { taskId, challenger, operator, operatorTree, challengerTree };
}

test("a withholding operator that abandons bisection is slashed by timeout, not accepted", async () => {
  const ctx = await deployFixture();
  const { provider, game, operator } = ctx;
  ctx.label = "timeout-op";
  const { taskId, challenger, operatorTree, challengerTree } = await driveToChallenged(ctx);

  // The challenger posts its branch for the first round; the operator (the
  // untrusted party) goes silent instead of revealing its subtree.
  const dispute = await game.getTaskDisputeState(taskId);
  const start = Number(dispute.disputeStart);
  const end = Number(dispute.disputeEnd);
  const challengerChildren = getSubtreeChildren(challengerTree, start, end);
  await (
    await game.connect(challenger).submitBisection(taskId, false, challengerChildren.left, challengerChildren.right)
  ).wait();

  const operatorBefore = await game.getParticipantStake(operator.address);
  const challengerBefore = await game.getParticipantStake(challenger.address);

  // Premature timeout is rejected; only after the round window elapses does
  // default judgment apply.
  await expectCallException(() => game.timeoutDispute(taskId), /CALL_EXCEPTION/);
  await advanceTime(provider, PAST_WINDOW_SECONDS);
  await (await game.timeoutDispute(taskId, { gasLimit: 1_000_000 })).wait();

  const status = await game.getTaskStatus(taskId);
  // Operator slashed, challenger compensated; crucially the result is NOT
  // marked accepted (decision != OperatorAccepted).
  assert.equal(Number(status.decision), 2, "decision must be OperatorSlashed");
  assert.notEqual(Number(status.decision), 1, "withheld result must never be accepted");
  assert.equal(Number(status.status), 3);
  assert.equal(
    await game.getParticipantStake(operator.address),
    operatorBefore - ethers.parseEther("0.5"),
    "operator loses the slash for abandoning the dispute"
  );
  assert.equal(
    await game.getParticipantStake(challenger.address),
    challengerBefore + ethers.parseEther("0.5"),
    "challenger is compensated from the slash"
  );
});

test("a challenger that abandons its own challenge forfeits the bond and the result is still not accepted", async () => {
  const ctx = await deployFixture();
  const { provider, game, operator } = ctx;
  ctx.label = "timeout-ch";
  const { taskId, challenger } = await driveToChallenged(ctx);

  // Neither side advances: the challenger, which bears the prosecution
  // burden, walks away. After the round window, default judgment forfeits
  // its bond to the operator.
  await advanceTime(provider, PAST_WINDOW_SECONDS);
  await (await game.timeoutDispute(taskId, { gasLimit: 1_000_000 })).wait();

  const status = await game.getTaskStatus(taskId);
  // The operator wins the bond but its result is not accepted by the
  // abandonment itself: the task returns to Auditing so that any other
  // eligible dissenter can still challenge; the abandoning challenger cannot.
  assert.equal(Number(status.decision), 0, "no decision: the task re-opened");
  assert.equal(Number(status.status), 1, "task must be back in Auditing");
  assert.equal(status.challengeTriggered, false);
  assert.equal(
    (await game.getParticipantStakeBreakdown(challenger.address)).lockedChallengeBondWei,
    0n,
    "the abandoned bond is forfeited, not locked"
  );
});

test("a continuity-violating trace yields an unresolvable dispute (griefing), never a wrong acceptance", async () => {
  const ctx = await deployFixture();
  const { provider, game, operator, auditors, decryptors } = ctx;

  // Honest challenger trace: the canonical leaves. Operator trace: leaf 2 is
  // internally self-consistent arithmetic but on a WRONG operand (a broken
  // dataflow wire), modelling an inter-leaf continuity violation rather than
  // a local arithmetic error. leaves[2] = MIN(15,7)=7; the operator feeds
  // lhs=6 and correctly reports MIN(6,7)=6, so its leaf differs from the
  // honest one in the OPERAND, not only in the result.
  const challengerTree = buildMerkleTree(leaves);
  const operatorBadLeaf = { ...leaves[2], lhs: 6, claimed: 6 };
  const operatorLeaves = [...leaves];
  operatorLeaves[2] = operatorBadLeaf;
  const operatorTree = buildMerkleTree(operatorLeaves);
  const taskId = ethers.encodeBytes32String("continuity");

  await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, operatorTree, operatorLeaves, ethers.id("result-continuity")))
  ).wait();
  await sampleTaskParticipants(game, taskId);

  const assignedAuditors = await assignedWallets(game, taskId, auditors, "getAssignedAuditors");
  const assignedDecryptors = await assignedWallets(game, taskId, decryptors, "getAssignedDecryptors");
  const leafHint = 2;
  const leafAuditors = await assignedWalletsForLeaf(game, taskId, leafHint, auditors);
  const challenger = leafAuditors[0];
  const challengeTranscript = buildChallengeAuditTranscript(
    taskId, challenger, operatorTree.root, leafHint, operatorBadLeaf, leaves[2]
  );

  const auditCommitments = [];
  for (const auditor of assignedAuditors) {
    const supportsOperator = auditor.address !== challenger.address;
    const covers = await game.isAuditorAssignedToLeaf(taskId, auditor.address, leafHint);
    const podRoot = supportsOperator
      ? ethers.keccak256(ethers.toUtf8Bytes(`pod:${auditor.address}`))
      : challengeTranscript.root;
    auditCommitments.push(
      await commitAudit(game, taskId, auditor, supportsOperator, podRoot, covers ? leafHint : undefined)
    );
  }

  await advanceToRevealWindow(provider, game, taskId);
  for (let i = 0; i < assignedAuditors.length; i += 1) {
    await openCommittedAudit(game, taskId, assignedAuditors[i], auditCommitments[i], assignedDecryptors.slice(0, 2));
  }
  await advancePastOpenWindow(provider, game, taskId);
  await proveDiligence(game, taskId, challenger, challengeTranscript);
  await (
    await game.connect(challenger).openChallenge(
      taskId, challengerTree.root, leafHint, challengeTranscript.errorDigest,
      challengeTranscript.leaves[0], challengeTranscript.proof, challengeTranscript.proofSiblingOnLeft
    )
  ).wait();

  // Bisection reaches the disputed leaf: the two sides agree on the prefix and
  // diverge at leaf 2.
  const dispute = await bisectToLeaf(game, taskId, operator, challenger, operatorTree, challengerTree);
  assert.equal(Number(dispute.disputeEnd) - Number(dispute.disputeStart), 1);

  // The objective verifier still cannot adjudicate a leaf whose operands
  // differ: it has no proof of which operand is the true prior output, so the
  // direct resolution reverts on the operand mismatch.
  await expectCallException(
    () =>
      game.resolveLeafDispute(
        taskId,
        traceLeafClaim(operatorBadLeaf),
        traceLeafClaim(leaves[2])
      ),
    /CALL_EXCEPTION/
  );

  // The terminal round nevertheless terminates. Default judgment applies to the
  // last round exactly as it does to every bisection round: past the deadline
  // the operator, which bears the burden of having its terminal claim
  // validated, is settled against. The challenger bond is returned rather than
  // locked forever, so an inconclusive leaf is an operator loss and not a
  // griefing residual.
  const challengerStakeBefore = await game.getParticipantStake(challenger.address);
  const operatorStakeBefore = await game.getParticipantStake(operator.address);
  await advanceTime(provider, PAST_WINDOW_SECONDS);
  await (await game.timeoutDispute(taskId)).wait();

  const status = await game.getTaskStatus(taskId);
  assert.equal(Number(status.status), 3, "the dispute terminates instead of stalling");
  assert.notEqual(Number(status.decision), 1, "a continuity-violating trace is never accepted");
  assert.equal(Number(status.decision), 2, "settlement is against the operator");
  assert.ok(
    (await game.getParticipantStake(operator.address)) < operatorStakeBefore,
    "the operator is slashed rather than keeping its stake"
  );
  assert.ok(
    (await game.getParticipantStake(challenger.address)) >= challengerStakeBefore,
    "the challenger bond is not locked forever"
  );
});
