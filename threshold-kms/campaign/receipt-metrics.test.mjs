import test from 'node:test';
import assert from 'node:assert/strict';
import {transactionCosts} from './receipt-metrics.mjs';
function fixture(){
 const receipt={gasUsed:21001n,gasPrice:1234567890123456789n,status:1};
 const tx={hash:'0x01',data:'0x010203',from:'owner',to:'contract',value:10n**21n,maxFeePerGas:10n**30n};
 return {receipt,tx,rows:[{hash:tx.hash,label:'owner-key',gasUsed:String(receipt.gasUsed)}],
         provider:{getTransaction:async()=>tx,getTransactionReceipt:async()=>receipt}};
}
test('fees use mined price with exact integer arithmetic and exclude principal',async()=>{
 const f=fixture();const result=await transactionCosts(f.provider,f.rows);
 assert.equal(f.rows[0].transactionFeeWei,String(f.receipt.gasUsed*f.receipt.gasPrice));
 assert.equal(f.rows[0].valueWei,String(f.tx.value));
 assert.equal(result.calldataBytes,3);assert.equal(result.receiptScopes.ownerAdmission.transactionCount,1);
});
test('zero-price QBFT fee is measured zero, not a market cost estimate',async()=>{
 const f=fixture();f.receipt.gasPrice=0n;await transactionCosts(f.provider,f.rows);
 assert.equal(f.rows[0].transactionFeeWei,'0');
});
test('missing/reverted receipt, missing price and changed gas fail closed',async()=>{
 for(const field of ['status','gasPrice','gasUsed']){
  const f=fixture();f.receipt[field]=field==='status'?0:field==='gasPrice'?null:1n;
  await assert.rejects(transactionCosts(f.provider,f.rows));
 }
});
