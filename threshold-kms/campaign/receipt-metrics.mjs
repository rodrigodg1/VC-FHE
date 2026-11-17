import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
import {scopedReceiptCosts} from './measurement-scopes.mjs';

// Measure the mined effective price, never the transaction's maximum fee cap.
// Deposited/transferred principal is recorded separately from transaction fees.
export async function transactionCosts(provider, receipts) {
 let calldataBytes=0;
 for(const r of receipts){
  const tx=await provider.getTransaction(r.hash??r.txHash);assert.ok(tx);
  const mined=await provider.getTransactionReceipt(tx.hash);
  assert.ok(mined&&mined.status===1&&typeof mined.gasPrice==='bigint');
  assert.equal(String(mined.gasUsed),String(r.gasUsed));
  r.effectiveGasPriceWei=String(mined.gasPrice);
  r.transactionFeeWei=String(mined.gasUsed*mined.gasPrice);
  r.valueWei=String(tx.value);r.status=mined.status;
  r.calldataBytes=ethers.getBytes(tx.data).length;r.from=tx.from;r.to=tx.to;r.dataDigest=ethers.keccak256(tx.data);
  calldataBytes+=r.calldataBytes;
 }
 return {transactionCount:receipts.length,gasUsed:receipts.reduce((a,r)=>a+BigInt(r.gasUsed),0n).toString(),
  calldataBytes,receiptScopes:scopedReceiptCosts(receipts)};
}
