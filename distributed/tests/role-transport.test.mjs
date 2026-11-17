import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {createRoleServer,callRole} from '../role-transport.mjs';

test('mTLS role binding, durable deduplication, no action replay after failure',async t=>{
  const temp=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-role-transport-'));
  t.after(()=>fs.rm(temp,{recursive:true,force:true}));
  const openssl=(...args)=>execFileSync('openssl',args,{cwd:temp,stdio:'ignore'});
  openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1','-subj','/CN=test-only-ca');
  async function certificate(name,server=false){
    openssl('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
    const ext='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'+
      'extendedKeyUsage='+ (server?'serverAuth':'clientAuth')+'\n'+(server?'subjectAltName=DNS:localhost\n':'');
    await fs.writeFile(path.join(temp,name+'.ext'),ext);
    openssl('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial',
      '-out',name+'.pem','-days','1','-extfile',name+'.ext');
    const key=await fs.readFile(path.join(temp,name+'.key')),cert=await fs.readFile(path.join(temp,name+'.pem'));
    return {key,cert,fingerprint256:new X509Certificate(cert).fingerprint256};
  }
  const ca=await fs.readFile(path.join(temp,'ca.pem'));
  const serverIdentity=await certificate('server',true),client=await certificate('client'),other=await certificate('other');
  let executions=0;
  const server=createRoleServer({campaign:'unit-test-only',node:'adjudicator-1',...serverIdentity,ca,
    peers:[{node:'coordinator-1',fingerprint256:client.fingerprint256,operations:['test-echo','test-failure']}],
    journal:path.join(temp,'journal'),handlers:{'test-echo':async body=>{executions++;return body;},
      'test-failure':async()=>{executions++;throw Error('synthetic failure');}}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const args={url:`https://localhost:${server.address().port}/v1/role`,...client,ca,
    serverFingerprint256:serverIdentity.fingerprint256,timeoutMs:5000};
  const request={id:'case-1',campaign:'unit-test-only',target:'adjudicator-1',sender:'coordinator-1',operation:'test-echo',body:{value:3}};
  const first=await callRole({...args,request});
  assert.equal(first.response.value.value,3);
  assert.equal(executions,1);
  assert.ok(first.metrics.requestJsonBytes>0);
  await callRole({...args,request});
  assert.equal(executions,1,'completed request must return the prior response without repeating work');
  await assert.rejects(callRole({...args,request:{...request,body:{value:4}}}),/reused/);
  await assert.rejects(callRole({...args,request:{...request,campaign:'different-campaign'}}),/binding/);
  await assert.rejects(callRole({...args,request:{...request,target:'adjudicator-2'}}),/binding/);
  await assert.rejects(callRole({...args,request:{...request,operation:'sign-anything'}}),/not authorized/);
  await assert.rejects(callRole({...args,...other,request}),/unrecognized/);
  await assert.rejects(callRole({...args,serverFingerprint256:'00'.repeat(32),request}),/identity mismatch/);
  assert.equal(executions,1);
  const failure={...request,id:'case-failure',operation:'test-failure'};
  await assert.rejects(callRole({...args,request:failure}),/failed/);
  assert.equal(executions,2);
  await assert.rejects(callRole({...args,request:failure}),/Reconcile/);
  assert.equal(executions,2,'failed action must not automatically execute again');
  // An interrupted journal entry must not be converted into a fresh request.
  const files=await fs.readdir(path.join(temp,'journal'));
  assert.equal(files.length,2);
  for(const name of files){
    const file=path.join(temp,'journal',name),state=JSON.parse(await fs.readFile(file,'utf8'));
    if(state.id==='case-failure')await fs.writeFile(file,JSON.stringify({...state,state:'started'}));
  }
  await assert.rejects(callRole({...args,request:failure}),/Reconcile/);
  assert.equal(executions,2);
});
