import ganache from "ganache";
import { ethers } from "ethers";
import fs from "node:fs";
import { compileContracts, boundCreateTaskArgs, buildMerkleTree, sampleTaskParticipants, merkleProofForLeafHashTree } from "./evm-lib.mjs";
const mnemonic="test test test test test test test test test test test junk";
const provider=new ethers.BrowserProvider(ganache.provider({logging:{quiet:true},chain:{chainId:31337},miner:{timestampIncrement:0},wallet:{mnemonic,totalAccounts:12}}));
const s=(i)=>provider.getSigner(i);
const deployer=await s(0),operator=await s(1);
const auditors=[await s(2),await s(3),await s(4)],decryptors=[await s(5),await s(6),await s(7)];
const A=await compileContracts();
const v=await new ethers.ContractFactory(A.ObjectiveMicroVerifier.abi,A.ObjectiveMicroVerifier.bytecode,deployer).deploy();await v.waitForDeployment();
const gameDeploy=await new ethers.ContractFactory(A.LegacyConfigurableDisputeGame.abi,A.LegacyConfigurableDisputeGame.bytecode,deployer).deploy(await v.getAddress(),20,20,20,false);
const game=await gameDeploy.waitForDeployment();
const gameRc=await gameDeploy.deploymentTransaction().wait();
const avDeploy=await new ethers.ContractFactory(A.TraceAvailability.abi,A.TraceAvailability.bytecode,deployer).deploy(await game.getAddress(),20);
const av=await avDeploy.waitForDeployment();
const avRc=await avDeploy.deploymentTransaction().wait();
await (await game.setAvailabilityModule(await av.getAddress())).wait();
await (await game.connect(operator).registerOperator({value:ethers.parseEther("2")})).wait();
for(const a of auditors) await (await game.connect(a).registerAuditor({value:ethers.parseEther("1")})).wait();
for(const d of decryptors) await (await game.connect(d).registerDecryptor({value:ethers.parseEther("1")})).wait();
const leaves=[{opcode:1,lhs:6,rhs:10,claimed:60},{opcode:2,lhs:60,rhs:2,claimed:30},{opcode:2,lhs:60,rhs:2,claimed:15},{opcode:4,lhs:15,rhs:7,claimed:7},{opcode:4,lhs:15,rhs:7,claimed:7},{opcode:5,lhs:7,rhs:1,claimed:1},{opcode:5,lhs:7,rhs:1,claimed:1},{opcode:5,lhs:7,rhs:1,claimed:1}];
const tree=buildMerkleTree(leaves);
const taskId=ethers.encodeBytes32String("gasmeas");
const createRc=await (await game.connect(operator).createTask(...boundCreateTaskArgs(taskId,tree,leaves,ethers.id("r")))).wait();
// sampleParticipants gas
await provider.send("evm_mine",[]); await provider.send("evm_mine",[]);
const sampleRc=await (await game.sampleParticipants(taskId,{gasLimit:1500000})).wait();
// availability
const assigned=await game.getAssignedAuditors(taskId);
let req; for(const a of auditors){ if(assigned.includes(await a.getAddress())){req=a;break;} }
let leafIndex=0; while(!(await game.isAuditorAssignedToLeaf(taskId,await req.getAddress(),leafIndex))) leafIndex++;
const bond=await av.REQUEST_BOND_WEI();
const reqRc=await (await av.connect(req).requestReveal(taskId,leafIndex,{value:bond})).wait();
const {proof}=merkleProofForLeafHashTree(tree,leafIndex);
const leaf=leaves[leafIndex];
const revRc=await (await av.connect(operator).reveal(taskId,0,leaf.opcode,leaf.lhs,leaf.rhs,leaf.claimed,proof)).wait();
// second task for markUnavailable path
const taskId2=ethers.encodeBytes32String("gasmeas2");
await (await game.connect(operator).createTask(...boundCreateTaskArgs(taskId2,tree,leaves,ethers.id("r2")))).wait();
await provider.send("evm_mine",[]); await provider.send("evm_mine",[]);
await (await game.sampleParticipants(taskId2,{gasLimit:1500000})).wait();
const assigned2=await game.getAssignedAuditors(taskId2);
let req2; for(const a of auditors){ if(assigned2.includes(await a.getAddress())){req2=a;break;} }
let li2=0; while(!(await game.isAuditorAssignedToLeaf(taskId2,await req2.getAddress(),li2))) li2++;
await (await av.connect(req2).requestReveal(taskId2,li2,{value:bond})).wait();
await provider.send("evm_increaseTime",[120]); await provider.send("evm_mine",[]);
const markRc=await (await av.markUnavailable(taskId2,0)).wait();

const rows=[
 ["createTask (incl. deferred sampling schedule)", createRc.gasUsed],
 ["sampleParticipants (assign auditors+decryptors)", sampleRc.gasUsed],
 ["requestReveal (bonded stage reveal request)", reqRc.gasUsed],
 ["reveal (leaf preimage + Merkle proof + bond payout)", revRc.gasUsed],
 ["markUnavailable (breach: slash operator + refund)", markRc.gasUsed],
 ["TraceAvailability deployment", avRc.gasUsed],
 ["DisputeGame deployment (with hardening)", gameRc.gasUsed],
];
let csv="mechanism,gas\n";
for(const [k,g] of rows){ console.log(g.toString().padStart(10), k); csv+=`"${k}",${g}\n`; }
fs.writeFileSync("artifacts/hardening_gas_results.csv",csv);
console.log("\nwrote artifacts/hardening_gas_results.csv");
process.exit(0);
