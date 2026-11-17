// Explicit diagnostic for the preserved, never-reserved first request.
// No signer, private key, FHE secret share or result-recovery call is available.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {ethers,compileReleasePolicy} from '/app/threshold-kms/campaign/onchain-policy.mjs';
import {requestBytes,deniedOnce} from './grpc-denial.mjs';
const cfg=JSON.parse(await fs.readFile('/config/campaign.json','utf8'));
const policy=JSON.parse(await fs.readFile('/config/release-policy.json','utf8'));
const wire=JSON.parse(await fs.readFile('/exchange/wire-0.json','utf8'));
const release=wire.releaseRequest;
assert.ok(ethers.isHexString(wire.request.slot,32),'missing authenticated consent slot');
assert.equal(cfg.executionProfile,'gcp-four-hosts-role-local-v1');
assert.equal(cfg.chainId,'46853');
const providers=cfg.ownerRpcUrls.map(url=>new ethers.JsonRpcProvider(url,undefined,{cacheTimeout:-1}));
try{
  const artifact=await compileReleasePolicy();
  const heads=await Promise.all(providers.map(p=>p.getBlockNumber()));const block=Math.min(...heads);
  const views=await Promise.all(providers.map(async p=>{
    assert.equal(String((await p.getNetwork()).chainId),cfg.chainId);
    const header=await p.getBlock(block),registry=new ethers.Contract(policy.address,artifact.abi,p);
    assert.equal(ethers.keccak256(await p.getCode(policy.address,block)),policy.runtimeCodeHash);
    const state=await registry.getRelease(release.requestId,{blockTag:block});
    assert.equal(state.exists,false,'old request exists on chain');
    assert.equal(await registry.requestBySlot(wire.request.slot,{blockTag:block}),ethers.ZeroHash,'old slot was consumed');
    const reservations=[];
    for(let start=Number(policy.deploymentBlock);start<=block;start+=2048){
      reservations.push(...await registry.queryFilter(registry.filters.ReleaseReserved(),start,Math.min(block,start+2047)));
    }
    assert.equal(reservations.length,0,'a previous release reservation exists');
    return {blockNumber:block,blockHash:header.hash,requestExists:false,slotUnused:true,totalReservations:0};
  }));
  assert.ok(views.every(v=>v.blockHash===views[0].blockHash),'validators disagree on pinned block');
  const payload=requestBytes(JSON.parse(Buffer.from(wire.wire,'hex').toString('utf8')));
  const results=[];
  for(let core=1;core<=4&&!process.argv.includes('--chain-only');core++){
    const result=await deniedOnce(`http://kms${core}:50100`,payload);
    results.push({core,...result});
  }
  console.log(JSON.stringify({schema:'preserved-unreserved-request-diagnostic-v1',views,results,
    allDenied:results.length===4&&results.every(r=>r.grpcStatus===7),resultRequested:false,transactionsSubmitted:0}));
}finally{for(const p of providers)p.destroy();}
