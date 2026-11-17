#!/usr/bin/env node
/**
 * Gas of the pre-challenge disclosure request path of
 * AuthenticatedTraceAvailability (the module the evaluation deploys), measured on
 * an in-process EVM with the same compiler settings as the QBFT deployment:
 *
 *   requestTraceDisclosure        bonded request by an assigned auditor
 *   publishDisputedTraceBatch     the operator answers with the whole trace
 *   withdrawBond                  the compliant operator collects the bond
 *   markDisputeTraceUnavailable   an unanswered request: slash + task closed
 *
 * Writes artifacts/disclosure_request_gas_results.csv. Not part of the
 * campaign's measured workloads: the evaluated disputes never use this path
 * (their traces are delivered off chain); it prices the deterrent.
 */
import ganache from "ganache";
import { ethers } from "ethers";
import fs from "node:fs";
import {
  authorizeAuthenticatedTask,
  boundCreateTaskArgs,
  buildMerkleTree,
  compileContracts,
  sampleTaskParticipants,
  terminalOutputBinding
} from "./evm-lib.mjs";

const WINDOW = 60;
const mnemonic = "test test test test test test test test test test test junk";
const provider = new ethers.BrowserProvider(
  ganache.provider({
    logging: { quiet: true },
    chain: { chainId: 31337, time: new Date("2025-01-01T00:00:00.000Z") },
    miner: { timestampIncrement: 0 },
    wallet: { mnemonic, totalAccounts: 12 }
  })
);
const s = (i) => provider.getSigner(i);
const requester = await s(0);
const operator = await s(1);
const auditors = [await s(2), await s(3), await s(4)];
const decryptors = [await s(5), await s(6), await s(7)];
const A = await compileContracts();

const clearVerifier = await new ethers.ContractFactory(
  A.ObjectiveMicroVerifier.abi, A.ObjectiveMicroVerifier.bytecode, requester
).deploy();
await clearVerifier.waitForDeployment();
const gameDeploy = await new ethers.ContractFactory(
  A.LegacyConfigurableDisputeGame.abi, A.LegacyConfigurableDisputeGame.bytecode, requester
).deploy(await clearVerifier.getAddress(), WINDOW, WINDOW, WINDOW, true);
const game = await gameDeploy.waitForDeployment();
const gameRc = await gameDeploy.deploymentTransaction().wait();
const avDeploy = await new ethers.ContractFactory(
  A.AuthenticatedTraceAvailability.abi, A.AuthenticatedTraceAvailability.bytecode, requester
).deploy(await game.getAddress(), WINDOW);
const availability = await avDeploy.waitForDeployment();
const avRc = await avDeploy.deploymentTransaction().wait();
await (await game.setAvailabilityModule(await availability.getAddress())).wait();
// secureTraceMode requires an FHEVM leaf verifier to be configured; the local
// adapter of the test-suite is used (never exercised by this measurement).
const acl = await new ethers.ContractFactory(A.LocalFhevmACL.abi, A.LocalFhevmACL.bytecode, requester).deploy();
await acl.waitForDeployment();
const executor = await new ethers.ContractFactory(A.LocalFhevmExecutor.abi, A.LocalFhevmExecutor.bytecode, requester).deploy();
await executor.waitForDeployment();
const kms = await new ethers.ContractFactory(A.LocalFhevmKMSVerifier.abi, A.LocalFhevmKMSVerifier.bytecode, requester)
  .deploy(await acl.getAddress(), await executor.getAddress());
await kms.waitForDeployment();
const fhevmVerifier = await new ethers.ContractFactory(A.FhevmObjectiveMicroVerifier.abi, A.FhevmObjectiveMicroVerifier.bytecode, requester)
  .deploy(await acl.getAddress(), await executor.getAddress(), await kms.getAddress());
await fhevmVerifier.waitForDeployment();
await (await game.setFhevmVerifier(await fhevmVerifier.getAddress())).wait();
await (await game.connect(operator).registerOperator({ value: ethers.parseEther("4") })).wait();
for (const a of auditors) await (await game.connect(a).registerAuditor({ value: ethers.parseEther("1") })).wait();
for (const d of decryptors) await (await game.connect(d).registerDecryptor({ value: ethers.parseEther("1") })).wait();

const leaves = [
  { opcode: 1, lhs: 6, rhs: 10, claimed: 60 },
  { opcode: 2, lhs: 60, rhs: 2, claimed: 15 },
  { opcode: 4, lhs: 15, rhs: 7, claimed: 7 },
  { opcode: 5, lhs: 7, rhs: 1, claimed: 1 },
  { opcode: 1, lhs: 1, rhs: 2, claimed: 2 },
  { opcode: 1, lhs: 2, rhs: 3, claimed: 6 },
  { opcode: 1, lhs: 6, rhs: 4, claimed: 24 },
  { opcode: 1, lhs: 24, rhs: 5, claimed: 120 }
];

async function createTask(label) {
  const taskId = ethers.encodeBytes32String(label);
  const tree = buildMerkleTree(leaves);
  const outputAttestationHash = ethers.id(`${label}-output`);
  const binding = terminalOutputBinding(taskId, tree, leaves, outputAttestationHash);
  const plan = await authorizeAuthenticatedTask({
    availability, requester, operatorAddress: operator.address, taskId, tree, leaves,
    resultHash: binding.resultHash, outputAttestationHash
  });
  await (await game.connect(operator).createTask(...boundCreateTaskArgs(taskId, tree, leaves, outputAttestationHash), { gasLimit: 3_000_000n })).wait();
  await sampleTaskParticipants(game, taskId);
  const assigned = await game.getAssignedAuditors(taskId);
  const auditor = auditors.find((a) => assigned.includes(a.address));
  return { taskId, plan, auditor };
}

// Answered request.
const t1 = await createTask("disclosure-answered");
const bond = await availability.requiredDisclosureBond(t1.taskId);
const reqRc = await (await availability.connect(t1.auditor).requestTraceDisclosure(t1.taskId, { value: bond, gasLimit: 500_000n })).wait();
const batch = t1.plan.disclosureLeaves;
const pubRc = await (
  await availability.connect(operator).publishDisputedTraceBatch(
    t1.taskId,
    batch.map((d) => d.leaf),
    batch.map((d) => d.lhsInputProof),
    batch.map((d) => d.rhsInputProof),
    { gasLimit: 8_000_000n }
  )
).wait();
const wdRc = await (await availability.connect(operator).withdrawBond({ gasLimit: 200_000n })).wait();

// Unanswered request.
const t2 = await createTask("disclosure-withheld");
await (await availability.connect(t2.auditor).requestTraceDisclosure(t2.taskId, { value: bond, gasLimit: 500_000n })).wait();
await provider.send("evm_increaseTime", [4 * WINDOW + 5]);
await provider.send("evm_mine", []);
const markRc = await (await availability.markDisputeTraceUnavailable(t2.taskId, { gasLimit: 1_000_000n })).wait();

const rows = [
  ["requestTraceDisclosure (bonded pre-challenge request, deadlines extended)", reqRc.gasUsed],
  [`publishDisputedTraceBatch (${leaves.length} leaves, complete trace, bond credited)`, pubRc.gasUsed],
  ["withdrawBond (compliant operator collects the request bond)", wdRc.gasUsed],
  ["markDisputeTraceUnavailable (pre-challenge breach: slash + task closed + refund)", markRc.gasUsed],
  ["AuthenticatedTraceAvailability deployment", avRc.gasUsed],
  ["DisputeGame deployment", gameRc.gasUsed]
];
let csv = "mechanism,gas\n";
for (const [k, g] of rows) {
  console.log(g.toString().padStart(10), k);
  csv += `"${k}",${g}\n`;
}
fs.mkdirSync("artifacts", { recursive: true });
fs.writeFileSync("artifacts/disclosure_request_gas_results.csv", csv);
console.log("\nwrote artifacts/disclosure_request_gas_results.csv");
process.exit(0);
