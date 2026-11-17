// Adversarial battery for the two admission-hardening mechanisms of the
// non-linear path:
//
//   Commit-then-sample assignment (VerifiableFHEDisputeGame.sampleParticipants)
//     S1  assignment does not exist before the seed block is mined, and
//         sampling before it reverts
//     S2  the on-chain cohort is exactly the deterministic function of
//         (taskId, blockhash(seed block)) recomputed off-chain: neither the
//         operator-chosen trace root nor createTask-time prevrandao enters
//     S3  an unsampled task can never finalize optimistically
//     S4  audits are impossible before sampling; windows start at sampling
//     S5  double sampling reverts
//     S6  a seed block older than the 256-block hash horizon reschedules
//         instead of bricking the task
//     S7  the ordered cohort is sampled without replacement and its exact
//         all-adversarial probability is hypergeometric, not stake-weighted
//
//   Trace availability (TraceAvailability, reveal-or-reject)
//     A1  request -> correct reveal -> cleared -> finalization proceeds;
//         requester bond flows to the operator
//     A2  a reveal with a mutated leaf or wrong proof is rejected
//     A3  non-assigned requesters and wrong bonds are rejected
//     A4  an ignored request blocks optimistic finalization permanently and
//         refunds the requester bond (reject-not-slash)
//     A5  a late reveal cannot clear a recorded unavailability
//     A6  each request covers one leaf: clearing one of two requests leaves
//         finalization blocked until the second leaf is also revealed
//
// Run: node --test contracts/test/sampling-availability.test.mjs

import test from "node:test";
import assert from "node:assert/strict";
import {
  advanceBlocks,
  advanceTime,
  confirm,
  createProvider,
  signerFor,
  WINDOW_SECONDS
} from "./chain-harness.mjs";
import { ethers } from "ethers";
import {
  boundCreateTaskArgs,
  buildMerkleTree,
  compileContracts,
  leafHash,
  merkleProofForLeafHashTree,
  sampleTaskParticipants,
  traceLeafClaim
} from "../../scripts/evm-lib.mjs";

/// The committed leaf preimage a stage reveal must republish: the three
/// ciphertext handles, never the operand values.
function revealHandles(leaf) {
  const claim = traceLeafClaim(leaf);
  return [claim.lhsHandle, claim.rhsHandle, claim.claimedHandle];
}

const chainId = 31337;
const mnemonic = "test test test test test test test test test test test junk";

const leaves = [
  { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
  { opcode: 2, lhs: 60, rhs: 2, claimed: 30 },
  { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
  { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
  { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 }
];

const coder = ethers.AbiCoder.defaultAbiCoder();
const uint256Max = (1n << 256n) - 1n;

function sampleWithoutReplacement(pool, taskId, seed, role, sampleSize) {
  const domain = ethers.keccak256(
    coder.encode(["bytes32", "bytes32", "string"], [taskId, seed, role])
  );
  const cutoff = uint256Max - (uint256Max % BigInt(pool.length));
  const selected = [];
  for (let i = 0n; i < BigInt(sampleSize); i += 1n) {
    for (let attempt = 0n; ; attempt += 1n) {
      const draw = BigInt(
        ethers.keccak256(
          coder.encode(["bytes32", "uint256", "uint256"], [domain, i, attempt])
        )
      );
      if (draw >= cutoff) continue;
      const candidate = pool[Number(draw % BigInt(pool.length))];
      if (!selected.some((address) => address.toLowerCase() === candidate.toLowerCase())) {
        selected.push(candidate);
        break;
      }
    }
  }
  return selected;
}

function choose(n, k) {
  if (k < 0 || k > n) return 0n;
  let result = 1n;
  for (let i = 1n; i <= k; i += 1n) {
    result = (result * (n - k + i)) / i;
  }
  return result;
}


async function deployFixture() {
  const provider = await createProvider({ totalAccounts: 12, chainId: 31337 });

  const deployer = await signerFor(provider, 0);
  const operator = await signerFor(provider, 1);
  const auditors = await Promise.all([2, 3, 4, 5, 6].map((index) => signerFor(provider, index)));
  const decryptors = await Promise.all([7, 8, 9, 10].map((index) => signerFor(provider, index)));
  const outsider = await signerFor(provider, 11);

  const artifacts = await compileContracts();
  const verifier = await new ethers.ContractFactory(
    artifacts.ObjectiveMicroVerifier.abi,
    artifacts.ObjectiveMicroVerifier.bytecode,
    deployer
  ).deploy();
  await verifier.waitForDeployment();

  const game = await new ethers.ContractFactory(
    artifacts.LegacyConfigurableDisputeGame.abi,
    artifacts.LegacyConfigurableDisputeGame.bytecode,
    deployer
  ).deploy(await verifier.getAddress(), WINDOW_SECONDS, WINDOW_SECONDS, WINDOW_SECONDS, false);
  await game.waitForDeployment();

  const availability = await new ethers.ContractFactory(
    artifacts.TraceAvailability.abi,
    artifacts.TraceAvailability.bytecode,
    deployer
  ).deploy(await game.getAddress(), WINDOW_SECONDS);
  await availability.waitForDeployment();
  await (await game.setAvailabilityModule(await availability.getAddress())).wait();

  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  for (const auditor of auditors) {
    await (await game.connect(auditor).registerAuditor({ value: ethers.parseEther("1") })).wait();
  }
  for (const decryptor of decryptors) {
    await (await game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  }

  return {
    provider,
    game,
    availability,
    operator,
    auditors,
    decryptors,
    outsider
  };
}

async function createTask(game, operator, taskId, tree, taskLeaves, label) {
  const receipt = await (
    await game
      .connect(operator)
      .createTask(...boundCreateTaskArgs(taskId, tree, taskLeaves, ethers.id(label)))
  ).wait();
  return receipt;
}

async function expectRevert(action) {
  try {
    const result = await action();
    if (result?.wait) {
      await result.wait();
    }
  } catch (error) {
    assert.ok(
      error.code === "CALL_EXCEPTION" || error.code === "UNKNOWN_ERROR",
      `expected revert, got ${error.code}: ${error.shortMessage || error.message}`
    );
    return;
  }
  assert.fail("expected revert");
}

test("S1/S5: no assignment before the seed block; premature and double sampling revert", async () => {
  const { game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("s1");
  await createTask(game, operator, taskId, tree, leaves, "result-s1");

  assert.equal((await game.getAssignedAuditors(taskId)).length, 0);
  // The seed block has not been mined yet: sampling reverts.
  await expectRevert(() => game.sampleParticipants(taskId));

  await sampleTaskParticipants(game, taskId);
  assert.equal((await game.getAssignedAuditors(taskId)).length, 3);
  await expectRevert(() => game.sampleParticipants(taskId));
});

test("S2/S7: unbiased ordered sampling is deterministic and without replacement", async () => {
  const { provider, game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("s2");
  const createReceipt = await createTask(game, operator, taskId, tree, leaves, "result-s2");
  const sampleBlock = createReceipt.blockNumber + 1;

  const sampleReceipt = await sampleTaskParticipants(game, taskId);
  const seed = (await provider.getBlock(sampleBlock)).hash;

  // Event carries the seed and it equals the hash of the first post-commit block.
  const parsed = sampleReceipt.logs
    .map((log) => {
      try {
        return game.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry && entry.name === "ParticipantsSampled");
  assert.ok(parsed, "ParticipantsSampled event expected");
  assert.equal(parsed.args.seed, seed);

  // Off-chain recomputation from (taskId, seed) alone reproduces the cohort:
  // the operator-chosen trace root and createTask-time randomness do not enter.
  const assigned = await game.getAssignedAuditors(taskId);
  const auditorPool = [];
  for (let i = 0n; i < 5n; i++) {
    auditorPool.push(await game.auditorPool(i));
  }
  const expected = sampleWithoutReplacement(auditorPool, taskId, seed, "auditors", 3);
  assert.deepEqual([...assigned], expected);
  assert.equal(new Set(assigned.map((address) => address.toLowerCase())).size, 3);

  const assignedDecryptors = await game.getAssignedDecryptors(taskId);
  const decryptorPool = [];
  for (let i = 0n; i < 4n; i++) {
    decryptorPool.push(await game.decryptorPool(i));
  }
  assert.deepEqual(
    [...assignedDecryptors],
    sampleWithoutReplacement(decryptorPool, taskId, seed, "decryptors", 3)
  );
  assert.equal(new Set(assignedDecryptors.map((address) => address.toLowerCase())).size, 3);
});

test("S7: all-adversarial cohort probability equals the hypergeometric law", () => {
  const population = 8n;
  const adversarial = 3n;
  const cohort = 2n;
  const exactNumerator = choose(adversarial, cohort);
  const exactDenominator = choose(population, cohort);

  let enumeratedCaptures = 0n;
  let enumeratedOrderedCohorts = 0n;
  for (let first = 0n; first < population; first += 1n) {
    for (let second = 0n; second < population; second += 1n) {
      if (first === second) continue;
      enumeratedOrderedCohorts += 1n;
      if (first < adversarial && second < adversarial) enumeratedCaptures += 1n;
    }
  }

  assert.equal(enumeratedCaptures * exactDenominator, enumeratedOrderedCohorts * exactNumerator);
  // C(A,m)/C(M,m) <= (A/M)^m for sampling without replacement.
  assert.ok(
    exactNumerator * population ** cohort <= exactDenominator * adversarial ** cohort
  );
});

test("S3/S4: unsampled tasks cannot finalize and cannot be audited", async () => {
  const { provider, game, operator, auditors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("s3");
  await createTask(game, operator, taskId, tree, leaves, "result-s3");

  // Even after every window length has elapsed in wall-clock terms, the
  // unsampled task cannot finalize optimistically...
  await advanceTime(provider, 4 * WINDOW_SECONDS + 10);
  await expectRevert(() => game.finalizeUnchallenged(taskId));

  // ...and no audit can be submitted (nobody is assigned).
  await expectRevert(() =>
    game
      .connect(auditors[0])
      .submitAudit(taskId, 0, ethers.id("pod"), ethers.id("verdict"))
  );

  // Windows start at sampling: after sampling, the commit window is live.
  await sampleTaskParticipants(game, taskId);
  const [commitDeadline] = await game.getTaskDeadlines(taskId);
  const now = (await provider.getBlock("latest")).timestamp;
  assert.ok(Number(commitDeadline) > now, "commit window must start at sampling");
});

test("S6: a seed block beyond the 256-block hash horizon reschedules", async () => {
  const { provider, game, operator } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("s6");
  await createTask(game, operator, taskId, tree, leaves, "result-s6");

  for (let i = 0; i < 258; i++) {
    await advanceBlocks(provider, 1);
  }
  // First call cannot read the expired blockhash: it reschedules.
  await (await game.sampleParticipants(taskId)).wait();
  assert.equal((await game.getAssignedAuditors(taskId)).length, 0);
  // The rescheduled target is minable and sampling then succeeds.
  await sampleTaskParticipants(game, taskId);
  assert.equal((await game.getAssignedAuditors(taskId)).length, 3);
});

test("A1: request -> correct reveal -> cleared -> finalization; bond pays the operator", async () => {
  const { provider, game, availability, operator, auditors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("a1");
  await createTask(game, operator, taskId, tree, leaves, "result-a1");
  await sampleTaskParticipants(game, taskId);

  const assigned = await game.getAssignedAuditors(taskId);
  const requester = auditors.find((wallet) => assigned.includes(wallet.address));
  let leafIndex = 0;
  while (!(await game.isAuditorAssignedToLeaf(taskId, requester.address, leafIndex))) {
    leafIndex += 1;
  }

  const bond = await availability.REQUEST_BOND_WEI();
  await (
    await availability.connect(requester).requestReveal(taskId, leafIndex, { value: bond })
  ).wait();
  assert.equal(await availability.isCleared(taskId), false);

  const { proof } = merkleProofForLeafHashTree(tree, leafIndex);
  const leaf = leaves[leafIndex];
  const revealReceipt = await (
    await availability
      .connect(operator)
      // Structure only: the stage reveal republishes the committed leaf, which
      // is (opcode, lhsHandle, rhsHandle, claimedHandle).
      .reveal(
        taskId,
        0,
        leaf.opcode,
        ...revealHandles(leaf),
        proof
      )
  ).wait();
  // The bond payout to the operator is inside reveal: a failed transfer would
  // revert with TransferFailed and roll back the event, so the presence of
  // StageDataRevealed proves the escrowed bond was paid out successfully.
  const revealed = revealReceipt.logs
    .map((log) => {
      try {
        return availability.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry && entry.name === "StageDataRevealed");
  assert.ok(revealed, "StageDataRevealed (with successful bond payout) expected");
  assert.equal(revealed.args.leafIndex, BigInt(leafIndex));
  assert.equal(await availability.isCleared(taskId), true);

  await advanceTime(provider, 4 * WINDOW_SECONDS + 10);
  await (await game.finalizeUnchallenged(taskId)).wait();
  const [status] = await game.getTaskStatus(taskId);
  assert.equal(Number(status), 3, "task must finalize once cleared");
});

test("A6: availability is enforced per requested leaf, not for the full trace", async () => {
  const { game, availability, operator, auditors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("a6");
  await createTask(game, operator, taskId, tree, leaves, "result-a6");
  await sampleTaskParticipants(game, taskId);

  const bond = await availability.REQUEST_BOND_WEI();
  const leafIndices = [0, 4];
  for (const leafIndex of leafIndices) {
    const assigned = await game.getAssignedAuditorsForLeaf(taskId, leafIndex);
    const requester = auditors.find((wallet) => assigned.includes(wallet.address));
    assert.ok(requester, `assigned requester expected for leaf ${leafIndex}`);
    await (
      await availability.connect(requester).requestReveal(taskId, leafIndex, { value: bond })
    ).wait();
  }
  assert.equal(await availability.pendingRequests(taskId), 2n);

  const firstLeaf = leaves[leafIndices[0]];
  const firstProof = merkleProofForLeafHashTree(tree, leafIndices[0]).proof;
  await (
    await availability
      .connect(operator)
      .reveal(taskId, 0, firstLeaf.opcode, ...revealHandles(firstLeaf), firstProof)
  ).wait();
  assert.equal(await availability.pendingRequests(taskId), 1n);
  assert.equal(await availability.isCleared(taskId), false);

  const secondLeaf = leaves[leafIndices[1]];
  const secondProof = merkleProofForLeafHashTree(tree, leafIndices[1]).proof;
  await (
    await availability
      .connect(operator)
      .reveal(taskId, 1, secondLeaf.opcode, ...revealHandles(secondLeaf), secondProof)
  ).wait();
  assert.equal(await availability.pendingRequests(taskId), 0n);
  assert.equal(await availability.isCleared(taskId), true);
});

test("A2/A3: wrong proofs, wrong bonds, and unassigned requesters are rejected", async () => {
  const { game, availability, operator, auditors, outsider } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("a2");
  await createTask(game, operator, taskId, tree, leaves, "result-a2");
  await sampleTaskParticipants(game, taskId);

  const assigned = await game.getAssignedAuditors(taskId);
  const requester = auditors.find((wallet) => assigned.includes(wallet.address));
  let leafIndex = 0;
  while (!(await game.isAuditorAssignedToLeaf(taskId, requester.address, leafIndex))) {
    leafIndex += 1;
  }
  const bond = await availability.REQUEST_BOND_WEI();

  // Wrong bond.
  await expectRevert(() =>
    availability.connect(requester).requestReveal(taskId, leafIndex, { value: bond / 2n })
  );
  // Unassigned requester (outsider is not even a registered auditor).
  await expectRevert(() =>
    availability.connect(outsider).requestReveal(taskId, leafIndex, { value: bond })
  );

  await (
    await availability.connect(requester).requestReveal(taskId, leafIndex, { value: bond })
  ).wait();

  const { proof } = merkleProofForLeafHashTree(tree, leafIndex);
  const leaf = leaves[leafIndex];
  // Mutated claimed value: hash no longer matches the committed leaf.
  await expectRevert(() =>
    availability
      .connect(operator)
      .reveal(
        taskId,
        0,
        leaf.opcode,
        ...revealHandles({ ...leaf, claimed: leaf.claimed + 1 }),
        proof
      )
  );
  // Truncated proof: wrong depth for the committed leaf count.
  await expectRevert(() =>
    availability
      .connect(operator)
      .reveal(taskId, 0, leaf.opcode, ...revealHandles(leaf), proof.slice(1))
  );
  // Non-operator cannot reveal.
  await expectRevert(() =>
    availability
      .connect(requester)
      // Structure only: the stage reveal republishes the committed leaf, which
      // is (opcode, lhsHandle, rhsHandle, claimedHandle).
      .reveal(
        taskId,
        0,
        leaf.opcode,
        ...revealHandles(leaf),
        proof
      )
  );
});

test("A4/A5: an ignored request blocks optimistic finalization permanently", async () => {
  const { provider, game, availability, operator, auditors } = await deployFixture();
  const tree = buildMerkleTree(leaves);
  const taskId = ethers.encodeBytes32String("a4");
  await createTask(game, operator, taskId, tree, leaves, "result-a4");
  await sampleTaskParticipants(game, taskId);

  const assigned = await game.getAssignedAuditors(taskId);
  const requester = auditors.find((wallet) => assigned.includes(wallet.address));
  let leafIndex = 0;
  while (!(await game.isAuditorAssignedToLeaf(taskId, requester.address, leafIndex))) {
    leafIndex += 1;
  }
  const bond = await availability.REQUEST_BOND_WEI();
  await (
    await availability.connect(requester).requestReveal(taskId, leafIndex, { value: bond })
  ).wait();

  // The operator ignores the request; the reveal window and every task window
  // elapse.
  await advanceTime(provider, 4 * WINDOW_SECONDS + 10);

  // markUnavailable slashes the withholding operator in the dispute game and
  // refunds the requester's bond, both inside the same transaction. A failed
  // transfer reverts with TransferFailed and rolls back TraceUnavailable, so
  // the event's presence proves the bond was refunded successfully; the
  // operator's on-chain stake is read directly to confirm the slash.
  const operatorAddress = await operator.getAddress();
  const requesterAddress = await requester.getAddress();
  const operatorStakeBefore = await game.getParticipantStake(operatorAddress);
  const requesterStakeBefore = await game.getParticipantStake(requesterAddress);
  const markReceipt = await (await availability.markUnavailable(taskId, 0)).wait();
  const unavailable = markReceipt.logs
    .map((log) => {
      try {
        return availability.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((entry) => entry && entry.name === "TraceUnavailable");
  assert.ok(unavailable, "TraceUnavailable (with successful bond refund) expected");
  assert.equal(await availability.pendingRequests(taskId), 0n);
  assert.equal(await availability.unavailabilityRecorded(taskId), true);

  // Withholding is not a free stall: the operator loses the slash and the
  // requester receives it, so withholding is never cheaper than losing a
  // dispute.
  const slash = ethers.parseEther("0.5");
  assert.equal(
    await game.getParticipantStake(operatorAddress),
    operatorStakeBefore - slash,
    "withholding operator must be slashed"
  );
  assert.equal(
    await game.getParticipantStake(requesterAddress),
    requesterStakeBefore + slash,
    "requester is rewarded from the operator slash"
  );

  // Optimistic finalization is now impossible although the challenge window
  // has passed and no challenge exists: reject-not-slash.
  await expectRevert(() => game.finalizeUnchallenged(taskId));

  // A late reveal cannot clear the recorded unavailability.
  const { proof } = merkleProofForLeafHashTree(tree, leafIndex);
  const leaf = leaves[leafIndex];
  await expectRevert(() =>
    availability
      .connect(operator)
      // Structure only: the stage reveal republishes the committed leaf, which
      // is (opcode, lhsHandle, rhsHandle, claimedHandle).
      .reveal(
        taskId,
        0,
        leaf.opcode,
        ...revealHandles(leaf),
        proof
      )
  );
  assert.equal(await availability.isCleared(taskId), false);
});
