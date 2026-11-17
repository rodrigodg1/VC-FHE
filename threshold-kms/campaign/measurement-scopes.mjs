// Exhaustive receipt accounting. Unknown labels fail rather than silently
// charging baseline/setup transactions to the proposed verification path.
import assert from 'node:assert/strict';
const labels={
 harness:['fund-owner'],
 deployment:['linear-deploy','deploy:ObjectiveMicroVerifier','deploy:VerifiableFHEDisputeGame', 'deploy:CanonicalFHEDisputeGame',
  'deploy:AuthenticatedTraceAvailability', 'deploy:CanonicalLeafVerifier', 'deploy:CanonicalBountyFHEDisputeGame', 'deploy:BountyTraceAvailability','setAvailabilityModule','setCanonicalLeafVerifier'],
 collateral:['registerOperator','registerAuditor','registerOpeningParticipant','operator-stake'],
 ownerAdmission:['owner-key','owner-admission','protected-record-binding','registerInputOrigins'],
 releaseSetup:['protected-record-registration','create-release-consent','approve-release-consent'],
 releaseAuthorization:['propose-exact-release','approve-exact-release','reserve-exact-release'],
 proposed:['authorizeTaskStatement','createTask','registerCanonicalContext','sampleParticipants',
  'finalizeUnchallenged','honestSubmitSealedAudit','honestRevealSealedAudit','honestClaimAuditBond','register-task','bound-result'],
 baseline:['deploy:CanonicalExecutionBaseline','acceptFullExecution'],
 dispute:['submitAudit','submitSealedAudit','revealSealedAudit','openVerdict','sealDiligenceRandomness','proveAuditDiligence',
  'openChallenge','publishDisputedTraceBatch','requestBountyTraceDisclosure','publishAuthenticatedTraceBatch','operatorBisection','relayOperatorBisection','relayChallengerBisection','challengerBisection',
  'advanceDispute','admitCanonicalLeaf','settleCanonicalLeaf','claimUnusedAuditBond','withdrawChallengeBounty']
};
const category=new Map(Object.entries(labels).flatMap(([scope,names])=>names.map(n=>[n,scope])));
export function receiptScope(label){assert.ok(category.has(label),'unclassified receipt: '+label);return category.get(label);}
export function scopedReceiptCosts(receipts){
 const scopes={},hashes=new Set();
 for(const r of receipts){
  const hash=r.hash??r.txHash;assert.ok(hash&&!hashes.has(hash),'missing/duplicate transaction');hashes.add(hash);
  const gas=BigInt(r.gasUsed);assert.ok(gas>=0n);
  assert.ok(Number.isSafeInteger(r.calldataBytes)&&r.calldataBytes>=0,'missing measured calldata length');
  const scope=receiptScope(r.label);
  const row=scopes[scope]??={transactionCount:0,gasUsed:0n,calldataBytes:0,transactions:[]};
  row.transactionCount++;row.gasUsed+=gas;row.calldataBytes+=r.calldataBytes;row.transactions.push(hash);
 }
 return Object.fromEntries(Object.entries(scopes).map(([k,v])=>[k,{...v,gasUsed:String(v.gasUsed)}]));
}
