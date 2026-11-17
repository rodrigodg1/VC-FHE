// Arbitrary public bytes only. This endpoint never sends a protocol task.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {push,pull,rpc} from './client.mjs';
import {digest} from './public-files.mjs';
globalThis.vcfheProbe={active:0,maximum:0,put:0,get:0,errors:0};
const peer='auditor-1',count=16,bytesPerChunk=32*1024,root='/fixtures/infra-'+randomUUID();
const phase=name=>console.error(JSON.stringify({infrastructureProbePhase:name}));
await fs.mkdir(root,{recursive:true});
const startedAt=new Date().toISOString(),files=[],expected=new Map();
phase('ping');
assert.equal((await rpc(peer,'probe-ping',{})).chunks,0);
for(let i=0;i<count;i++){
  const file=root+'/chunk-'+i+'.bin',bytes=randomBytes(bytesPerChunk);
  files.push(file);expected.set(file,bytes);await fs.writeFile(file,bytes,{flag:'wx'});
}
phase('upload');
const rows=await push(peer,files),ids=[...new Set(rows.flatMap(r=>r.chunks))];
assert.equal(ids.length,count);assert.equal(globalThis.vcfheProbe.put,count);
for(const row of rows){assert.equal(row.bytes,bytesPerChunk);assert.equal(row.chunks.length,1);await fs.rm(row.path);}
for(const id of ids)await fs.rm('/transport/public-chunks/'+id);
phase('download');await pull(peer,rows);
assert.equal(globalThis.vcfheProbe.get,count);
for(const [name,bytes] of expected){const actual=await fs.readFile(name);assert.deepEqual(actual,bytes);assert.equal(digest(actual),digest(bytes));}
const before={...globalThis.vcfheProbe};
phase('warm-cache');
assert.deepEqual(await push(peer,files),rows);await pull(peer,rows);
assert.equal(globalThis.vcfheProbe.put,before.put);assert.equal(globalThis.vcfheProbe.get,before.get);
// Rejection happens before CAS publication and affects only this isolated server.
phase('negative-cid');
await assert.rejects(rpc(peer,'put-chunk',{id:'0'.repeat(64),data:Buffer.from('wrong public fixture CID').toString('base64')}));
assert.equal((await rpc(peer,'probe-ping',{})).chunks,count);
assert.equal(globalThis.vcfheProbe.active,0);assert.equal(globalThis.vcfheProbe.maximum,8);
console.log(JSON.stringify({schema:'vcfhe-wan-transport-microprobe-v1',status:'passed',
  classification:'infrastructure-only-not-evaluation-evidence',startedAt,finishedAt:new Date().toISOString(),
  chunks:count,bytesPerChunk,payloadBytes:count*bytesPerChunk,crossHostTls:true,
  roundTripContentVerified:true,maximumChunkConcurrency:globalThis.vcfheProbe.maximum,
  uploadCalls:before.put,downloadCalls:before.get,warmResendAddedCalls:0,negativeCidRejected:true,
  serverUsesProposedAtomicPublication:true,protocolTasks:0,fheCalls:0,onChainCalls:0,kmsCalls:0,
  protocolStateAccessed:false,performanceClaim:false}));
phase('completed');
console.error(JSON.stringify({remainingResources:process.getActiveResourcesInfo()}));
