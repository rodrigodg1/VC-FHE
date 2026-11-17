import test from 'node:test';
import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
import {ownerInputOrigins,approveInputOrigins} from './owner-admission.mjs';
import {publicTracePlan} from '../../fhe-pod/scripts/canonical-chain.mjs';
import {compileComplianceCircuit} from '../../fhe-pod/scripts/compliance-circuit.mjs';
const address=n=>ethers.getAddress('0x'+n.toString(16).padStart(40,'0'));
const task=ethers.id('approved task'),fault=ethers.id('approved fault task');
const inputs=n=>Array.from({length:n},(_,i)=>({owner:address(i%6+1),handle:ethers.id('unit ciphertext '+i)}));
function request(records,owner=records[0].owner,taskId=task){
 const rows=ownerInputOrigins(records,owner,taskId);
 return {inputs:records,owner,taskIds:[task,fault],handles:rows.map(r=>r.handle),metadata:rows.map(r=>r.metadataHash)};
}
test('n=50 owner has nine real records plus exactly fourteen public padding entries',()=>{
 const records=inputs(50),snapshot=JSON.stringify(records),r=request(records);
 assert.equal(r.handles.length,23);assert.ok(approveInputOrigins(r));
 assert.equal(JSON.stringify(records),snapshot);assert.equal(records.length,50);
 assert.equal(request(records,address(2)).handles.length,9);
 assert.ok(approveInputOrigins(request(records,records[0].owner,fault)));
});
for(const n of [1,2,16,32,50,64,100,128])test(`canonical exact padding for ${n} inputs`,()=>{
 const records=inputs(n);let count=0;
 for(const owner of new Set(records.map(r=>r.owner))){const r=request(records,owner);assert.ok(approveInputOrigins(r));count+=r.handles.length;}
 assert.equal(count,2**Math.ceil(Math.log2(n)));
});
test('reject substituted/reordered/missing/extra/duplicated padding and real inputs',()=>{
 const r=request(inputs(50));
 for(const mutate of [
  v=>v.handles[9]=ethers.id('forged padding'),v=>v.metadata[9]=ethers.id('forged metadata'),
  v=>v.handles[0]=ethers.id('forged ciphertext'),v=>v.metadata[0]=ethers.id('forged real metadata'),
  v=>{v.handles.pop();v.metadata.pop();},v=>{v.handles.push(v.handles[9]);v.metadata.push(v.metadata[9]);},
  v=>{v.handles[10]=v.handles[9];v.metadata[10]=v.metadata[9];},
  v=>{v.handles.reverse();v.metadata.reverse();},v=>v.taskIds=[ethers.id('unapproved task')],
  v=>v.owner=address(2),v=>v.metadata.pop(),v=>{v.handles=[];v.metadata=[];}
 ]){const changed=structuredClone(r);mutate(changed);assert.throws(()=>approveInputOrigins(changed));}
});
for(const regional of [false,true])for(const n of [16,32,50])test(`independent owner agrees with production compiler/trace plan: regional=${regional} n=${n}`,()=>{
 const program=compileComplianceCircuit({recordCount:n,regional,poorThresholdMilli:2000,targetPermille:950,targetCell:474859250});
 const records=inputs(program.inputs.length);
 // Synthetic handles only for structural regression; never experiment evidence.
 const results=program.instructions.map((_,i)=>ethers.id('unit result '+i));
 const handle=ref=>ref.kind==='input'?records[ref.index].handle:ref.kind==='output'?results[ref.index]:ethers.id('unit constant '+ref.value);
 const manifest={leaves:program.instructions.map((r,i)=>({...r,lhsHandle:handle(r.lhs),rhsHandle:handle(r.rhs),resultHandle:results[i]}))};
 for(const id of [task,fault]){
  const {plan}=publicTracePlan(id,{inputs:records},manifest),groups=new Map();
  for(const row of plan.inputRecords){const owner=records[row.sourceIndex]?.owner??records[0].owner;
   if(!groups.has(owner))groups.set(owner,[]);groups.get(owner).push(row);}
  for(const [owner,rows] of groups)assert.ok(approveInputOrigins({inputs:records,owner,taskIds:[task,fault],
   handles:rows.map(r=>r.ciphertextHandle),metadata:rows.map(r=>r.metadataHash)}));
 }
});
