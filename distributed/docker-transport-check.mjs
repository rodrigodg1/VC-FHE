// Infrastructure-only Docker check. No FHE, KMS operation or workflow is simulated.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {configuration,rpc,push,pull} from './client.mjs';
import {callRole} from './role-transport.mjs';
const cfg=await configuration();
const results=[];
const bytes=randomBytes(1024*1024+37);
const file='/release-evidence/docker-check/transport-payload.bin';
await fs.mkdir('/release-evidence/docker-check',{recursive:true});
await fs.writeFile(file,bytes,{flag:'wx'});
const peers=cfg.peers.filter(p=>p.node!==cfg.node);
// Test original public chunk handlers and the actual client across containers.
for(const peer of peers){
  const rows=await push(peer.node,[file]);
  const denied={name:'unsupported-test-operation',body:{},files:rows,outputs:[]};
  await assert.rejects(rpc(peer.node,'task',denied),/failed/);
  // A failed request must remain non-replayable across a container restart.
  if(peer.node==='kms-1'){
    const requestId='failed-'+randomUUID();
    await assert.rejects(rpc(peer.node,'task',denied,{id:requestId}),/failed/);
    await assert.rejects(rpc(peer.node,'task',denied,{id:requestId}),/Reconcile/);
    await fs.writeFile('/reports/restart-request.json',JSON.stringify({target:peer.node,id:requestId,body:denied}));
  }
  await assert.rejects(rpc(peer.node,'put-chunk',{id:'0'.repeat(64),data:bytes.subarray(0,17).toString('base64')}),/failed/);
  await assert.rejects(rpc(peer.node,'public-manifest',{paths:['/identity/tls.key']}),/failed/);
  results.push({node:peer.node,authenticated:true,chunks:rows[0].chunks.length,
    invalidOperationRejected:true,corruptChunkRejected:true,privatePathRejected:true});
}
// Install/return an ordinary public test file using the real KMS witness handler.
// This does not invoke a core or manufacture a decryption response.
for(const peer of peers.filter(p=>p.node.startsWith('kms-'))){
  const rows=await push(peer.node,[file]);
  const eventId=randomUUID();
  const body={name:'kms-evidence',body:{},files:rows,outputs:[]};
  const first=await rpc(peer.node,'task',body,{id:eventId});
  const second=await rpc(peer.node,'task',body,{id:eventId});
  assert.deepEqual(first,second);
  await assert.rejects(rpc(peer.node,'task',{...body,outputs:[file]},{id:eventId}),/reused/);
  const published=await rpc(peer.node,'public-manifest',{paths:[file]});
  assert.ok(published.ready);await pull(peer.node,published.files);
  assert.deepEqual(await fs.readFile(file),bytes);
}
const peer=peers.find(p=>p.node==='kms-1');
const credentials={url:peer.url,key:await fs.readFile(cfg.tls.key),cert:await fs.readFile(cfg.tls.cert),
  ca:await fs.readFile(cfg.tls.ca),serverFingerprint256:peer.fingerprint256,timeoutMs:5000};
const request={id:randomUUID(),campaign:cfg.campaign,target:peer.node,sender:cfg.node,
  operation:'public-manifest',body:{paths:[file]}};
await assert.rejects(callRole({...credentials,request:{...request,campaign:'wrong-campaign'}}),/binding/);
await assert.rejects(callRole({...credentials,serverFingerprint256:'0'.repeat(64),request}),/identity mismatch/);
const unprivileged=JSON.parse(await fs.readFile('/config/unprivileged.json','utf8'));
await assert.rejects(callRole({...credentials,key:await fs.readFile(unprivileged.key),cert:await fs.readFile(unprivileged.cert),
  request:{...request,sender:'owner-1',operation:'task',body:{name:'kms-evidence',body:{},files:[],outputs:[]}}}),/not authorized/);
await fs.writeFile('/reports/transport-check.json',JSON.stringify({schema:'vcfhe-docker-transport-check-v1',
  status:'passed',scope:'Authenticated public transport in separate Docker containers only',peers:results,
  kmsPublicWitnessHandlers:4,kmsCoreOperationsExecuted:0,fheWorkflowsExecuted:0,
  wrongCampaignRejected:true,wrongCertificateRejected:true,nonCoordinatorActionRejected:true},null,2));
console.log('DOCKER_TRANSPORT_CHECK_PASSED '+results.length+' participant endpoints');
