import test from 'node:test';
import assert from 'node:assert/strict';
import {receiptScope,scopedReceiptCosts} from './measurement-scopes.mjs';
test('receipt scopes reconcile exactly and do not mix baseline, deployment or collateral with proposal',()=>{
 const labels=['linear-deploy','owner-key','owner-admission','protected-record-binding','protected-record-registration',
  'create-release-consent','approve-release-consent','propose-exact-release','approve-exact-release','reserve-exact-release',
  'bound-result','operator-stake',
  'deploy:CanonicalExecutionBaseline','acceptFullExecution','openChallenge','publishDisputedTraceBatch','settleCanonicalLeaf'];
 const receipts=labels.map((label,i)=>({label,txHash:`tx-${i}`,gasUsed:String(i+1),calldataBytes:4*i}));
 const scopes=scopedReceiptCosts(receipts);
 assert.equal(scopes.proposed.transactionCount,1);
 assert.equal(scopes.baseline.transactionCount,2);
 assert.equal(scopes.releaseSetup.transactionCount,3);
 assert.equal(scopes.releaseAuthorization.transactionCount,3);
 assert.equal(scopes.dispute.transactionCount,3);
 assert.equal(Object.values(scopes).reduce((a,v)=>a+v.transactionCount,0),17);
 assert.equal(Object.values(scopes).reduce((a,v)=>a+BigInt(v.gasUsed),0n),153n);
 assert.equal(Object.values(scopes).reduce((a,v)=>a+v.calldataBytes,0),544);
 assert.equal(Object.values(scopes).flatMap(v=>v.transactions).length,17);
});
test('unknown labels and incomplete or duplicate receipts cannot enter evaluation accounting',()=>{
 assert.throws(()=>receiptScope('new-unreviewed-operation'));
 const receipt={label:'bound-result',hash:'tx',gasUsed:'1',calldataBytes:32};
 assert.throws(()=>scopedReceiptCosts([receipt,receipt]));
 for(const patch of [{hash:null},{gasUsed:'-1'},{calldataBytes:undefined},{calldataBytes:1.5}]){
  assert.throws(()=>scopedReceiptCosts([{...receipt,...patch}]));
 }
 assert.deepEqual(scopedReceiptCosts([]),{});
});
