/**
 * ROLE: contract administrator.
 *
 * Deploys MKLHS-Verification.sol with the task's public statement, which the
 * experiment fixes at deployment: dataset reference, scale, input count N, the
 * authorized operation (SUM/SUB), the non-zero dataset/epoch tag, and one
 * enrolled owner address per index. Then assigns the one-shot task to the
 * operator account. The administrator holds no signing or decryption key: it
 * cannot admit records, alter the accumulator, or read any data.
 *
 * Usage:
 *   node clients/01-deploy.mjs [caseLabel]        # default: first payload case
 *   RPC_URL=http://host:8545 node clients/01-deploy.mjs
 */
import { ethers } from "ethers";
import { loadCase, connect, roles, writeState, compileContract } from "./common.mjs";

const { entry } = loadCase();
const { accounts } = await connect();
const { deployer, operator, ownerSigner } = roles(accounts, entry.n);

console.log(`case      : ${entry.label} (n=${entry.n}, op=${entry.allowed_op === 0 ? "SUM" : "SUB"})`);
console.log(`datasetTag: ${entry.dataset_tag}`);

const { abi, bytecode } = compileContract();
const owners = await Promise.all(entry.records.map((r) => ownerSigner(r.index).getAddress()));
const factory = new ethers.ContractFactory(abi, bytecode, deployer);
const contract = await factory.deploy(
  entry.label, 1, entry.n, entry.allowed_op, entry.dataset_tag, owners,
  { value: ethers.parseEther("1") }
);
const rcpt = await contract.deploymentTransaction().wait();
const address = await contract.getAddress();
console.log(`deployed  : ${address} (gas ${rcpt.gasUsed})`);

const taskId = ethers.keccak256(ethers.toUtf8Bytes(`${entry.label}/task-1`));
await (await contract.connect(deployer).registerTask(taskId, await operator.getAddress())).wait();
console.log(`task      : ${taskId} assigned to operator ${await operator.getAddress()}`);

writeState(entry.label, {
  rpcUrl: process.env.RPC_URL ?? "http://127.0.0.1:8545",
  label: entry.label,
  contract: address,
  taskId,
  n: entry.n,
  owners,
  admitted: false,
  submitted: false,
});
console.log(`state     : clients/state.${entry.label}.json written`);
console.log("next      : node clients/02-owners.mjs " + entry.label);
