import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {CHUNK_BYTES,digest,manifest,install,publicPath,putBlob} from '../public-files.mjs';
import {authorizeTask,localIdentity,ownerIndex} from '../adapter-policy.mjs';
test('chunked public ciphertext transfer checks every byte and preserves source',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-public-'));
  const source=root+'/source',dest=root+'/dest',cas=root+'/cas';
  await fs.mkdir(source+'/fixtures/case',{recursive:true});
  const bytes=Buffer.alloc(CHUNK_BYTES+17,181);
  await fs.writeFile(source+'/fixtures/case/output.ct',bytes);
  const rows=await manifest(['/fixtures/case'],{root:source,cas});
  assert.equal(rows[0].chunks.length,2);
  await install(rows,cas,{root:dest});
  assert.deepEqual(await fs.readFile(dest+'/fixtures/case/output.ct'),bytes);
  assert.deepEqual(await fs.readFile(source+'/fixtures/case/output.ct'),bytes);
  await fs.writeFile(cas+'/'+rows[0].chunks[0],'corrupt');
  await assert.rejects(install(rows,cas,{root:dest}),/integrity mismatch/);
  assert.deepEqual(await fs.readFile(dest+'/fixtures/case/output.ct'),bytes);
});
test('private paths, traversal and symlinks are rejected',async()=>{
  for(const p of ['/identity/signing.hex','/recipient/result-0.json','/private/vault','/owner/expected.json',
    '/keyset/signing.pem','/fixtures/a/../secret','/fixtures/a/.hidden','/fixtures/a/private.key'])
    assert.throws(()=>publicPath(p));
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-symlink-'));
  await fs.mkdir(root+'/fixtures');await fs.symlink(os.tmpdir(),root+'/fixtures/linked');
  await assert.rejects(manifest(['/fixtures/linked'],{root}),/symlink/);
});
test('chunk hash and length are enforced',async()=>{
  const cas=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-cas-'));
  await assert.rejects(putBlob(cas,'0'.repeat(64),Buffer.from('wrong')),/integrity/);
  const bytes=Buffer.alloc(CHUNK_BYTES+1);
  await assert.rejects(putBlob(cas,digest(bytes),bytes),/integrity/);
});
test('local worker queue is excluded from an enclosing public case transfer',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-queue-'));
  await fs.mkdir(root+'/fixtures/case/.worker-jobs',{recursive:true});
  await fs.writeFile(root+'/fixtures/case/.worker-jobs/job.json','local bookkeeping');
  await fs.writeFile(root+'/fixtures/case/cipher.ct','encrypted bytes');
  const rows=await manifest(['/fixtures/case'],{root});
  assert.deepEqual(rows.map(r=>r.path),['/fixtures/case/cipher.ct']);
  assert.throws(()=>publicPath('/fixtures/case/.worker-jobs/job.json'));
});
test('fixed role tasks reject arbitrary execution and identity substitution',()=>{
  assert.throws(()=>authorizeTask('auditor',{name:'canonical-attest',body:{},files:[],outputs:[]}));
  assert.throws(()=>authorizeTask('operator',{name:'shell',body:{command:'true'},files:[],outputs:[]}));
  assert.throws(()=>authorizeTask('operator',{name:'canonical-execute',body:{args:['decrypt','/fixtures/a','/fixtures/b']},files:[],outputs:[]}));
  assert.throws(()=>localIdentity({identityFile:'role:adjudicator-2'},{node:'adjudicator-1'}));
  const bound=localIdentity({identityFile:'role:adjudicator-1',binary:'/tmp/evil'},{node:'adjudicator-1'});
  assert.equal(bound.identityFile,'/identity/signing.hex');assert.equal(bound.binary,'/usr/local/bin/kms-campaign');
  assert.throws(()=>ownerIndex({index:1,action:'transaction'},{ownerIndex:0}));
});
