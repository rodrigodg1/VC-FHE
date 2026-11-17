// Structural contract regression only: synthetic opaque handles, isolated local
// EVM and controlled time. Never campaign/FHE/KMS or QBFT timing evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createRequire} from 'node:module';
import {ethers,buildMerkleTree,ciphertextHandleForClear} from '../../fhe-pod/scripts/evm-lib.mjs';
import {canonicalDisclosureBatches,canonicalAuditorFunding} from '../../fhe-pod/scripts/canonical-game-driver.mjs';
import {publicTracePlan} from '../../fhe-pod/scripts/canonical-chain.mjs';
import {compileComplianceCircuit} from '../../fhe-pod/scripts/compliance-circuit.mjs';
const require=createRequire(new URL('../../fhe-pod/package.json',import.meta.url));
const solc=require('solc'),ganache=require('ganache');
test('auditor funding follows trace depth, minimum stake and deployed penalty constants',()=>{
 for(const [n,expected] of [[1,'1'],[64,'1'],[128,'1'],[256,'1'],[512,'1.1'],[1024,'1.2']]){
  assert.equal(canonicalAuditorFunding(n,...['1','.2','.1','.5'].map(ethers.parseEther)),ethers.parseEther(expected));
 }
 for(const n of [0,3,50,NaN,Infinity,2**32])assert.throws(()=>canonicalAuditorFunding(n,1n,2n,3n,4n));
 assert.equal(canonicalAuditorFunding(1,1n,2n,3n,4n),4n);
 assert.throws(()=>canonicalAuditorFunding(8,1n,-1n,1n,1n));
});

test('batching preserves every row and order; historical default eight; fail closed on invalid sizes',()=>{
 for(const n of [1,63,64,65,128,256,512]){
  const rows=Array.from({length:n},(_,i)=>({i}));
  for(const size of [undefined,1,8,32,64]){
   const chunks=canonicalDisclosureBatches(rows,size);
   assert.equal(chunks.length,Math.ceil(n/(size??8)));
   assert.deepEqual(chunks.flat(),rows);
   assert.ok(chunks.every(c=>c.length>0&&c.length<=(size??8)));
  }
 }
 for(const size of [0,-1,65,1.5,NaN,Infinity,'64',null])assert.throws(()=>canonicalDisclosureBatches([],size));
});

test('64-leaf batches reconstruct all roots within 20M gas, and retain authorization/proof/deadline rejection',async()=>{
 const source=await fs.readFile(new URL('../../fhe-pod/contracts/src/AuthenticatedTraceAvailability.sol',import.meta.url),'utf8');
 // Only substitutes the game caller/callback in this module-isolation test.
 const harness='pragma solidity ^0.8.24; contract Caller { address immutable operator=msg.sender; function getTaskStatus(bytes32) external view returns(uint8,uint8,bool,address,address) { return (2,0,true,operator,address(0)); } function forward(address a, bytes calldata d) external { (bool ok,bytes memory r)=a.call(d); if(!ok) assembly { revert(add(r,32),mload(r)) } } function extendDeadlinesForDisclosure(bytes32,uint64) external {} }';
 const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'A.sol':{content:source},'Caller.sol':{content:harness}},settings:{evmVersion:'paris',viaIR:true,optimizer:{enabled:true,runs:1},metadata:{bytecodeHash:'none'},outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.deepEqual((compiled.errors??[]).filter(e=>e.severity==='error'),[]);
 const rpc=ganache.provider({logging:{quiet:true},chain:{chainId:31337},miner:{timestampIncrement:0,blockGasLimit:30000000}});
 const provider=new ethers.BrowserProvider(rpc,undefined,{cacheTimeout:-1});
 try {
  const signer=await provider.getSigner(0),other=await provider.getSigner(1),address=await signer.getAddress();
  const deploy=async(file,name,args=[])=>{const a=compiled.contracts[file][name];const c=await new ethers.ContractFactory(a.abi,a.evm.bytecode.object,signer).deploy(...args);await c.waitForDeployment();return c;};
  const caller=await deploy('Caller.sol','Caller'),availability=await deploy('A.sol','AuthenticatedTraceAvailability',[caller.target,120]);
  const forward=async(method,args)=>{await(await caller.forward(availability.target,availability.interface.encodeFunctionData(method,args))).wait();};
  const setup=async(regional,n,label)=>{
   const task=ethers.id(label),program=compileComplianceCircuit({recordCount:n,regional,poorThresholdMilli:2000,targetPermille:950,targetCell:474859250});
   const inputs=program.inputs.map((_,i)=>({owner:address,handle:ethers.id(label+' input '+i)}));
   const results=program.instructions.map((_,i)=>ethers.id(label+' result '+i));
   const handle=r=>r.kind==='input'?inputs[r.index].handle:r.kind==='output'?results[r.index]:ciphertextHandleForClear(r.value);
   const manifest={leaves:program.instructions.map((r,i)=>({...r,lhsHandle:handle(r.lhs),rhsHandle:handle(r.rhs),resultHandle:results[i]}))};
   const {leaves,plan}=publicTracePlan(task,{inputs},manifest),tree=buildMerkleTree(leaves),artifact=ethers.id(label+' artifact'),result=ethers.id(label+' bound result');
   for(const rows of canonicalDisclosureBatches(plan.inputRecords,64))await(await availability.registerInputOrigins(rows.map(r=>r.ciphertextHandle),rows.map(r=>r.metadataHash),{gasLimit:20000000})).wait();
   const now=(await provider.getBlock('latest')).timestamp;
   await(await availability.authorizeTaskStatement(task,address,tree.root,result,plan.inputTree.root,plan.inputTree.leafCount,plan.programTree.root,plan.provenanceTree.root,leaves.length,artifact,now+86400)).wait();
   await forward('consumeTaskAuthorization',[task,address,tree.root,result,leaves.length,artifact]);
   await assert.rejects(availability.openDisputeTrace.staticCall(task));
   await forward('openDisputeTrace',[task]);
   return {task,plan};
  };
  const args=(task,rows)=>[task,rows.map(r=>r.leaf),rows.map(r=>r.lhsInputProof),rows.map(r=>r.rhsInputProof)];
  for(const regional of [false,true])for(const n of [16,32,50]){
   const {task,plan}=await setup(regional,n,`batch-${regional}-${n}`),batches=canonicalDisclosureBatches(plan.disclosureLeaves,64);
   await assert.rejects(availability.connect(other).publishDisputedTraceBatch.staticCall(...args(task,batches[0])));
   const forged=structuredClone(batches[0]);forged[0].leaf.lhsHandle=ethers.id('substituted ciphertext');
   await assert.rejects(availability.publishDisputedTraceBatch.staticCall(...args(task,forged)));
   let maxGas=0n;
   for(const rows of batches){
    const receipt=await(await availability.publishDisputedTraceBatch(...args(task,rows),{gasLimit:20000000})).wait();
    assert.equal(receipt.status,1);assert.ok(receipt.gasUsed<20000000n);maxGas=receipt.gasUsed>maxGas?receipt.gasUsed:maxGas;
   }
   assert.equal(await availability.nextDisclosureIndex(task),BigInt(plan.disclosureLeaves.length));
   assert.equal(await availability.isDisputeReady(task),true);
   await assert.rejects(availability.publishDisputedTraceBatch.staticCall(...args(task,batches[0])));
   console.log(JSON.stringify({kind:'isolated-contract-gas-regression',regional,n,leaves:plan.disclosureLeaves.length,batches:batches.length,maxGas:String(maxGas)}));
  }
  const {task,plan}=await setup(true,50,'expired-batch');
  await rpc.request({method:'evm_increaseTime',params:[121]});await rpc.request({method:'evm_mine',params:[]});
  await assert.rejects(availability.publishDisputedTraceBatch.staticCall(...args(task,canonicalDisclosureBatches(plan.disclosureLeaves,64)[0])));
  assert.equal(await availability.nextDisclosureIndex(task),0n);assert.equal(await availability.isDisputeReady(task),false);
 } finally {provider.destroy();await rpc.disconnect();}
});
