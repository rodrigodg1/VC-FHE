import test from "node:test";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import { createProvider, signerFor, advanceTime } from "./chain-harness.mjs";
import { compileContracts, boundCreateTaskArgs, buildMerkleTree,
  sampleTaskParticipants } from "../../scripts/evm-lib.mjs";

async function fixture(secure = false) {
  const provider = await createProvider({ totalAccounts: 10, chainId: 31337 });
  const signers = await Promise.all(Array.from({ length: 8 }, (_, i) => signerFor(provider, i)));
  const [deployer, operator] = signers;
  const artifacts = await compileContracts();
  const deploy = async (name, args = []) => {
    const contract = await new ethers.ContractFactory(artifacts[name].abi,
      artifacts[name].bytecode, deployer).deploy(...args);
    await contract.waitForDeployment(); return contract;
  };
  const verifier = await deploy("ObjectiveMicroVerifier");
  const game = await deploy("LegacyConfigurableDisputeGame", [verifier.target, 200, 200, 200, secure]);
  const bytes = ethers.getBytes(await provider.getCode(game.target)).length;
  assert.ok(bytes <= 24_576, `EIP-170 runtime exceeded: ${bytes}`);
  console.log(`deployed game runtime: ${bytes} bytes`);
  return { provider, game, deployer, operator, auditors: signers.slice(2, 5),
    decryptors: signers.slice(5), deploy };
}

test("secure deployment cannot enable auditor-selected KMS decryption", async () => {
  const { game, deployer } = await fixture(true);
  await assert.rejects(game.setKmsVerdictVerifier(deployer.address));
  assert.equal(await game.kmsVerdictVerifier(), ethers.ZeroAddress);
});

test("concurrent missing-opening penalties consume available stake without blocking closure", async () => {
  const { game, provider, operator, auditors, decryptors, deployer } = await fixture();
  await (await game.connect(operator).registerOperator({ value: ethers.parseEther("2") })).wait();
  for (const auditor of auditors) {
    await (await game.connect(auditor).registerAuditor({ value: ethers.parseEther("1") })).wait();
  }
  for (const decryptor of decryptors) {
    await (await game.connect(decryptor).registerDecryptor({ value: ethers.parseEther("1") })).wait();
  }
  const leaves = [{ opcode: 6, lhs: 1, rhs: 1, claimed: 2 }];
  const tree = buildMerkleTree(leaves);
  const tasks = [];
  for (let i = 0; i < 3; i++) {
    const taskId = ethers.id(`concurrent-auditor-exposure-${i}`);
    await (await game.connect(operator).createTask(...boundCreateTaskArgs(
      taskId, tree, leaves, ethers.id(`artifact-${i}`)))).wait();
    await sampleTaskParticipants(game, taskId);
    assert.ok((await game.getAssignedAuditors(taskId)).includes(auditors[0].address));
    tasks.push(taskId);
  }
  await advanceTime(provider, 601);
  const payments = [];
  for (const taskId of tasks) {
    const receipt = await (await game.slashLazyAuditor(taskId, auditors[0].address)).wait();
    const event = receipt.logs.map(log => {
      try { return game.interface.parseLog(log); } catch { return null; }
    }).find(event => event?.name === "LazyAuditorSlashed");
    payments.push(event.args[3]);
    await assert.rejects(async () =>
      (await game.slashLazyAuditor(taskId, auditors[0].address)).wait());
    await (await game.finalizeUnchallenged(taskId)).wait();
  }
  assert.deepEqual(payments, [ethers.parseEther("0.5"), ethers.parseEther("0.5"), 0n]);
  assert.equal(await game.getParticipantStake(auditors[0].address), 0n);
  assert.equal(await game.getParticipantStake(deployer.address), ethers.parseEther("1"));
});
