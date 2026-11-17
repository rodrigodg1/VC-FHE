// Read-only V3 policy snapshot for continuation planning and final accounting.
// Runs in the original image on the Besu network: no identity, no transaction,
// no KMS access. All four validators must agree at one pinned block.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {ethers} from './common.mjs';
import {loadReleasePolicy} from './onchain-policy.mjs';
const request=JSON.parse(process.env.VCFHE_RECOVERY_READ);
const config=JSON.parse(await fs.readFile('/config/release-policy.json','utf8'));
const providers=Array.from({length:4},(_,i)=>new ethers.JsonRpcProvider(`http://node${i+1}:8545`,undefined,{cacheTimeout:-1}));
const policy=(await loadReleasePolicy(providers[0])).contract;
const blockNumber=await providers[0].getBlockNumber();
const block=await providers[0].getBlock(blockNumber);
const views=await Promise.all(providers.map(async provider=>{
 const contract=policy.connect(provider),blockTag=blockNumber;
 assert.equal((await provider.getBlock(blockNumber)).hash,block.hash,'validators disagree on the pinned block');
 const records={},slots={};
 for(const id of request.records){
  const r=await contract.protectedRecords(id,{blockTag});
  records[id]={owner:r.owner,recordReference:r.recordReference,releaseLimit:Number(r.releaseLimit),spent:Number(r.spent)};
 }
 for(const label of request.slots){
  const slot=ethers.id(label);slots[label]={slot,requestId:await contract.requestBySlot(slot,{blockTag})};
 }
 return {records,slots};
}));
for(const view of views.slice(1))assert.deepEqual(view,views[0],'validator views differ');
for(const provider of providers)provider.destroy();
console.log(JSON.stringify({policy:config.address,blockNumber,blockHash:block.hash,...views[0]}));
