// Read-only readiness continuation snapshot. No signer, private vault or KMS.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {ethers} from './common.mjs';
import {loadReleasePolicy} from './onchain-policy.mjs';
import {compileContracts} from './runtime/scripts/evm-lib.mjs';
const request=JSON.parse(process.env.VCFHE_RECOVERY_READ);
const config=JSON.parse(await fs.readFile('/config/release-policy.json','utf8'));
const providers=Array.from({length:4},(_,i)=>new ethers.JsonRpcProvider(`http://node${i+1}:8545`,undefined,{cacheTimeout:-1}));
const policy=(await loadReleasePolicy(providers[0])).contract;
const blockNumber=await providers[0].getBlockNumber(),block=await providers[0].getBlock(blockNumber);
const views=await Promise.all(providers.map(async provider=>{
 assert.equal((await provider.getBlock(blockNumber)).hash,block.hash,'validators disagree on pinned block');
 const contract=policy.connect(provider),records={},slots={};
 for(const id of request.records){
  const row=await contract.protectedRecords(id,{blockTag:blockNumber});
  records[id]={owner:row.owner,recordReference:row.recordReference,releaseLimit:Number(row.releaseLimit),spent:Number(row.spent)};
 }
 for(const label of request.slots){const slot=ethers.id(label);slots[label]={slot,requestId:await contract.requestBySlot(slot,{blockTag:blockNumber})};}
 let failedTransaction;
 if(request.failedTransaction){
  const tx=await provider.getTransaction(request.failedTransaction),receipt=await provider.getTransactionReceipt(request.failedTransaction);
  assert.ok(tx&&receipt);assert.equal(tx.blockHash,receipt.blockHash);
  failedTransaction={hash:tx.hash,to:tx.to,from:tx.from,blockNumber:receipt.blockNumber,
   blockHash:receipt.blockHash,status:receipt.status,gasUsed:String(receipt.gasUsed),gasLimit:String(tx.gasLimit),data:tx.data};
 }
 let completedDispute;
 if(request.completedDispute){
  const {game,availability,taskId,transactions}=request.completedDispute;
  const g=new ethers.Contract(game,['function getTaskStatus(bytes32) view returns(uint8,uint8,bool,address,address)'],provider);
  const a=new ethers.Contract(availability,['function nextDisclosureIndex(bytes32) view returns(uint256)'],provider);
  const receipts=await Promise.all(transactions.map(async hash=>{
   const [tx,r]=await Promise.all([provider.getTransaction(hash),provider.getTransactionReceipt(hash)]);
   assert.ok(tx&&r&&r.blockNumber<=blockNumber);assert.equal(tx.blockHash,r.blockHash);
   return {txHash:hash,blockNumber:r.blockNumber,blockHash:r.blockHash,status:r.status,
    from:tx.from,to:tx.to,gasUsed:String(r.gasUsed),gasLimit:String(tx.gasLimit),
    effectiveGasPriceWei:String(r.gasPrice),transactionFeeWei:String(r.gasUsed*r.gasPrice),
    valueWei:String(tx.value),calldataBytes:ethers.getBytes(tx.data).length,dataDigest:ethers.keccak256(tx.data),
    logs:r.logs.map(l=>({address:l.address,topics:Array.from(l.topics),data:l.data}))};
  }));
  completedDispute={game,availability,taskId,
   state:Array.from(await g.getTaskStatus(taskId,{blockTag:blockNumber})).map(v=>typeof v==='bigint'?Number(v):v),
   disclosedLeaves:Number(await a.nextDisclosureIndex(taskId,{blockTag:blockNumber})),receipts};
 }
 return {records,slots,...(failedTransaction?{failedTransaction}:{}),...(completedDispute?{completedDispute}:{})};
}));
for(const view of views.slice(1))assert.deepEqual(view,views[0],'validator views differ');
const result={policy:config.address,blockNumber,blockHash:block.hash,...views[0]};
if(result.failedTransaction){
 await fs.mkdir('/tmp/vcfhe-compiled-contracts',{recursive:true});
 const artifacts=await compileContracts(),iface=new ethers.Interface(artifacts.BountyTraceAvailability.abi);
 const decoded=iface.parseTransaction({data:result.failedTransaction.data});
 result.failedTransaction.method=decoded.name;result.failedTransaction.rows=decoded.args[1].length;
 result.failedTransaction.calldataDigest=ethers.keccak256(result.failedTransaction.data);
 delete result.failedTransaction.data;
}
for(const provider of providers)provider.destroy();
console.log(JSON.stringify(result));
