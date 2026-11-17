// Independently derive exactly what the owner may sign, from its own approved
// input snapshot. Padding is public Merkle-tree structure, never a new dataset
// record, ciphertext operand, consent or release-budget identity.
import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
const coder=ethers.AbiCoder.defaultAbiCoder();
export function ownerInputOrigins(inputs,owner,taskId){
 assert.ok(Array.isArray(inputs)&&inputs.length>0&&inputs.length<2**31,'invalid approved input count');
 const who=ethers.getAddress(owner),first=ethers.getAddress(inputs[0].owner);
 const rows=inputs.flatMap((r,index)=>ethers.getAddress(r.owner)===who?[{
  handle:r.handle,metadataHash:ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,index,'record']))
 }]:[]);
 if(who===first){
  let padded=1;while(padded<inputs.length)padded*=2;
  for(let index=inputs.length;index<padded;index++)rows.push({
   handle:ethers.keccak256(ethers.solidityPacked(['string','bytes32','uint32'],['VCFHE_INPUT_TREE_PADDING',taskId,index])),
   metadataHash:ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,index,'padding']))
  });
 }
 return rows;
}
export function approveInputOrigins({inputs,owner,taskIds,handles,metadata}){
 assert.ok(taskIds.length>0&&handles.length>0,'empty origin authorization');
 assert.equal(handles.length,metadata.length,'origin metadata length mismatch');
 assert.ok(taskIds.some(taskId=>{
  const expected=ownerInputOrigins(inputs,owner,taskId);
  return expected.length===handles.length&&expected.every((r,i)=>r.handle===handles[i]&&r.metadataHash===metadata[i]);
 }),'owner refuses changed input origins or noncanonical padding');
 return true;
}
