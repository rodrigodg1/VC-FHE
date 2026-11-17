// Read-only reconciliation. No signer, identity, KMS key or submit call is used.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {ethers,compileReleasePolicy} from '/app/threshold-kms/campaign/onchain-policy.mjs';
const read=async p=>JSON.parse(await fs.readFile(p,'utf8'));
const app=await read('/reconciliation/application.json');
const prepared=await read('/reconciliation/prepared.json');
const request=await read('/reconciliation/request.json');
const cfg=app.config, policy=await read('/config/release-policy.json');
assert.equal(app.cases.length,10);assert.equal(app.kmsCalls,10);
assert.deepEqual(app.cases.map(c=>c.name),request.completed);
assert.deepEqual(prepared.cases.map(c=>c.name),request.completed.concat(request.remaining));
const providers=cfg.ownerRpcUrls.map(url=>new ethers.JsonRpcProvider(url,undefined,{cacheTimeout:-1}));
assert.equal(providers.length,4);
try{
 const artifact=await compileReleasePolicy();
 const heads=await Promise.all(providers.map(p=>p.getBlockNumber()));
 const block=Math.min(...heads)-1;assert.ok(block>0);
 const views=await Promise.all(providers.map(async p=>{
  assert.equal(String((await p.getNetwork()).chainId),String(cfg.chainId));
  const header=await p.getBlock(block),registry=new ethers.Contract(policy.address,artifact.abi,p);
  assert.equal(ethers.keccak256(await p.getCode(policy.address,block)),policy.runtimeCodeHash);
  const records={},reservations=[],consents=[],proposals=[];
  for(let start=Number(policy.deploymentBlock);start<=block;start+=2048){
   const end=Math.min(block,start+2047);
   reservations.push(...await registry.queryFilter(registry.filters.ReleaseReserved(),start,end));
   consents.push(...await registry.queryFilter(registry.filters.ConsentCreated(),start,end));
   proposals.push(...await registry.queryFilter(registry.filters.ReleaseProposed(),start,end));
  }
  assert.deepEqual(reservations.map(e=>e.args.requestId).sort(),app.cases.map(c=>c.releaseRequestId).sort(),
   'Additional or missing release requires specific reconciliation');
  assert.deepEqual(proposals.map(e=>e.args.requestId).sort(),app.cases.map(c=>c.releaseRequestId).sort(),
   'Uncompleted release proposal requires specific reconciliation');
  const historical=request.historicalConsents;
  assert.ok(Array.isArray(historical));
  const consentIds=app.cases.map(c=>c.consentId).concat(historical.map(c=>c.consentId));
  assert.equal(new Set(consentIds).size,consentIds.length);
  assert.deepEqual(consents.map(e=>e.args.consentId).sort(),consentIds.sort(),
   'Additional or missing consent requires specific reconciliation');
  for(const c of historical){
   const event=consents.find(e=>e.args.consentId===c.consentId);assert.ok(event);
   if(c.transactionHash)assert.equal(event.transactionHash,c.transactionHash);
   assert.equal(event.args.slot,c.slot);
   assert.equal(await registry.requestBySlot(c.slot,{blockTag:block}),ethers.ZeroHash,
    'Historical failed consent has a release and needs separate reconciliation');
   const state=await registry.getConsent(c.consentId,{blockTag:block});assert.ok(state.exists);
   assert.equal(state.slot,c.slot);
   if(c.authorization){
    assert.equal(c.slot,ethers.id(`${c.sourceRunId}:${c.caseName}:final:onchain-v3`));
    const a=c.authorization;
    for(const field of ['chainId','workflowKind','taskId','contextDigest','programDigest','programRoot',
      'profileDigest','keysetDigest','keyId','keyEpoch','mpcContext','recipient','slot'])
     assert.equal(String(state[field]).toLowerCase(),String(a[field]).toLowerCase());
    assert.equal(state.workflow.toLowerCase(),a.game.toLowerCase());
    assert.equal(state.domain,a.policyDomain);assert.equal(a.policy.toLowerCase(),policy.address.toLowerCase());
    const r=c.releaseRequest;
    assert.equal(r.consentId,c.consentId);
    assert.equal((await registry.getRelease(r.requestId,{blockTag:block})).exists,false,
     'Original recipient request was proposed and requires specific reconciliation');
    assert.equal(await registry.requestByKey(r.requestKey,{blockTag:block}),ethers.ZeroHash);
   }
  }
  for(const c of app.cases){
   const release=await registry.getRelease(c.releaseRequestId,{blockTag:block});
   assert.ok(release.exists&&release.reserved);
   assert.equal(await registry.requestBySlot(c.releaseSlot,{blockTag:block}),c.releaseRequestId);
   assert.equal(await registry.requestByKey(c.requestKey,{blockTag:block}),c.releaseRequestId);
   const receipt=await p.getTransactionReceipt(c.reservationTransaction);
   assert.equal(receipt.status,1);assert.equal(receipt.blockHash,c.reservationBlockHash);
   assert.equal((await p.getBlock(receipt.blockNumber)).hash,c.reservationBlockHash);
  }
  for(const name of request.remaining)for(const runId of [cfg.runId,request.nextRunId]){
   const slot=ethers.id(`${runId}:${name}:final:onchain-v3`);
   assert.equal(await registry.requestBySlot(slot,{blockTag:block}),ethers.ZeroHash,'Pending slot already consumed');
   assert.ok(!consents.some(e=>e.args.slot===slot),'Pending case already has consent');
  }
  const claims=new Map();
  for(const c of prepared.cases)for(let i=0;i<c.recordIds.length;i++){
   const id=c.recordIds[i],value={owner:c.owners[i],recordReference:c.recordReferences[i],releaseLimit:c.releaseLimits[i],initialSpent:c.initialSpent[i]};
   if(claims.has(id))assert.deepEqual(claims.get(id),value);
   claims.set(id,value);
  }
  for(const [id,claim] of claims){
   const r=await registry.protectedRecords(id,{blockTag:block});
   const charges=app.cases.filter(c=>c.recordIds.includes(id)).length;
   const needed=prepared.cases.slice(10).filter(c=>c.recordIds.includes(id)).length;
   if(r.owner===ethers.ZeroAddress){
    assert.equal(charges,0);assert.ok(claim.initialSpent+needed<=claim.releaseLimit);
    records[id]={...claim,spent:claim.initialSpent,registered:false};
   }else{
    assert.equal(r.owner.toLowerCase(),claim.owner.toLowerCase());
    assert.equal(r.recordReference,claim.recordReference);assert.equal(Number(r.releaseLimit),claim.releaseLimit);
    const baseline=app.protectedRecordBaselines[id]?.spent??claim.initialSpent;
    assert.equal(Number(r.spent),baseline+charges,'Unexpected cumulative counter delta');
    assert.ok(Number(r.spent)+needed<=claim.releaseLimit,'Insufficient remaining record quota');
    records[id]={owner:r.owner,recordReference:r.recordReference,releaseLimit:Number(r.releaseLimit),spent:Number(r.spent),registered:true};
   }
  }
  // Detect unreported confirmed transactions after the completed prefix.
  const nonces={};
  for(const r of app.receipts){
   const hashes=[r.transactionHash,r.hash,r.txHash].filter(Boolean);
   assert.ok(hashes.length&&hashes.every(h=>h===hashes[0])&&/^0x[0-9a-fA-F]{64}$/.test(hashes[0]),'Missing or inconsistent receipt hash');
   const hash=hashes[0];
   const tx=await p.getTransaction(hash);assert.ok(tx&&tx.blockNumber<=block);
   const from=tx.from.toLowerCase();nonces[from]=Math.max(nonces[from]??-1,tx.nonce);
  }
  for(const [from,nonce] of Object.entries(nonces))assert.equal(await p.getTransactionCount(from,block),nonce+1,
   'Unreported signer transaction after the completed prefix');
  return {blockNumber:block,blockHash:header.hash,records,reservations:reservations.map(e=>e.args.requestId),
   consentIds:consents.map(e=>e.args.consentId),historicalUnusedConsents:historical,nonces};
 }));
 for(const v of views.slice(1))assert.deepEqual(v,views[0],'Pinned validator views differ');
 console.log(JSON.stringify({schema:'completed-prefix-chain-reconciliation-v1',status:'reconciled',
  completed:request.completed,remaining:request.remaining,transactionsSubmitted:0,views}));
}finally{for(const p of providers)p.destroy();}
