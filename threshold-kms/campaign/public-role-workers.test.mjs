import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {measuredJsonCommand} from './adjudicator-metrics.mjs';

// Copy the actual proxy source into a temporary runtime. Only its public
// canonical implementation is replaced. No worker RPC, chain or FHE is run.
const directory=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-public-role-proxies-'));
await fs.mkdir(path.join(directory,'runtime','scripts'),{recursive:true});
await fs.writeFile(path.join(directory,'runtime','scripts','canonical-protocol.mjs'),`
import fs from 'node:fs/promises';
async function invoke(method,args){
 await fs.appendFile(process.env.TEST_PUBLIC_CALLS,JSON.stringify({method,args})+'\\n');
 if(process.env.TEST_PUBLIC_FAILURE)throw new Error(process.env.TEST_PUBLIC_FAILURE);
 return JSON.parse(process.env.TEST_PUBLIC_RESULT);
}
export const runCanonicalBinary=(...args)=>invoke('runCanonicalBinary',args);
export const detectCanonicalFault=(...args)=>invoke('detectCanonicalFault',args);
`);
for(const filename of ['public-operation-worker.mjs','public-audit-worker.mjs'])
 await fs.copyFile(new URL(filename,import.meta.url),path.join(directory,filename));

const profiles=[{
 name:'operator',filename:'public-operation-worker.mjs',purpose:'operator-execution',
 method:'runCanonicalBinary',
 request:{binary:'/usr/local/bin/kms-campaign',args:['execute-canonical','/fixtures/public inputs','/fixtures/operator-output']},
 result:{elapsedMs:12.5,outputs:['00ff'],traceRoot:'0x1234',nested:{valid:true}}
},{
 name:'auditor',filename:'public-audit-worker.mjs',purpose:'auditor-full-recomputation',
 method:'detectCanonicalFault',
 request:{context:{profile:{fixedFFT:true,threads:1},programDigest:'0x42'},binary:'/usr/local/bin/kms-campaign',
  publicDir:'/fixtures/public inputs',operatorDir:'/fixtures/operator-output',replayDir:'/fixtures/auditor-output'},
 result:{index:3,reason:'byte-mismatch',evidence:{replayMs:8.75},expected:'0x00',actual:'0xff'}
}];
function expectedCall(profile){
 return {method:profile.method,args:profile.name==='operator'
  ?[profile.request.binary,profile.request.args]:[profile.request]};
}
async function options(profile,suffix,failure){
 const calls=path.join(directory,profile.name+'-'+suffix+'.calls.jsonl');
 return {calls,env:{...process.env,TEST_PUBLIC_CALLS:calls,TEST_PUBLIC_RESULT:JSON.stringify(profile.result),
  TEST_PUBLIC_FAILURE:failure??''}};
}
async function observedCalls(file){
 return (await fs.readFile(file,'utf8')).trim().split('\n').map(JSON.parse);
}
async function invokeDirect(profile,env,input=JSON.stringify(profile.request)){
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[path.join(directory,profile.filename)],{env,stdio:['pipe','pipe','pipe']});
  let stdout='',stderr='';
  child.stdout.on('data',value=>{stdout+=value;});child.stderr.on('data',value=>{stderr+=value;});
  child.on('error',reject);child.on('close',(code,signal)=>resolve({code,signal,stdout,stderr}));
  child.stdin.on('error',error=>{if(error.code!=='EPIPE')reject(error);});
  // The real proxy accumulates stdin before parsing it. Split delivery must not
  // create multiple invocations or change the request passed to the runtime.
  const split=Math.floor(input.length/2);child.stdin.write(input.slice(0,split));child.stdin.end(input.slice(split));
 });
}

for(const profile of profiles){
 test(`${profile.name} proxy invokes the original API once and returns exactly its JSON`,async()=>{
  const {env,calls}=await options(profile,'direct');
  const result=await invokeDirect(profile,env);
  assert.equal(result.code,0);assert.equal(result.signal,null);assert.equal(result.stderr,'');
  assert.equal(result.stdout,JSON.stringify(profile.result)+'\n');
  assert.deepEqual(await observedCalls(calls),[expectedCall(profile)]);
 });

 test(`${profile.name} proxy preserves dispatch under the real resource wrapper`,async()=>{
  const {env,calls}=await options(profile,'measured');
  const result=await measuredJsonCommand({command:process.execPath,args:[path.join(directory,profile.filename)],
   input:profile.request,env,outputDir:directory,measurementId:profile.name+'-measured',
   role:profile.name,purpose:profile.purpose,executionScope:'controller-only-remote-fhe-excluded'});
  assert.deepEqual(result.value,profile.result);
  assert.deepEqual(await observedCalls(calls),[expectedCall(profile)]);
  assert.equal(result.measurement.status,'completed');
  assert.equal(result.measurement.executionScope,'controller-only-remote-fhe-excluded');
  assert.equal(result.measurement.nativeFheElapsedMs,null);
 });

 test(`${profile.name} proxy preserves runtime failure and the wrapper retains failed resource evidence`,async()=>{
  const message=profile.name+' fixture canonical operation failed';
  const {env,calls}=await options(profile,'failure',message);
  await assert.rejects(measuredJsonCommand({command:process.execPath,args:[path.join(directory,profile.filename)],
   input:profile.request,env,outputDir:directory,measurementId:profile.name+'-failure',
   role:profile.name,purpose:profile.purpose,executionScope:'controller-only-remote-fhe-excluded'}),error=>{
    assert.ok(error.message.includes(message));assert.equal(error.measurement.status,'failed');
    assert.equal(error.measurement.exitCode,1);assert.equal(error.measurement.nativeFheElapsedMs,null);
    return true;
   });
  assert.deepEqual(await observedCalls(calls),[expectedCall(profile)]);
  const raw=JSON.parse(await fs.readFile(path.join(directory,profile.name+'-failure.resources.json'),'utf8'));
  assert.equal(raw.exitCode,1);assert.ok(raw.elapsedMs>=0);
 });

 test(`${profile.name} proxy rejects malformed stdin before invoking the runtime`,async()=>{
  const {env,calls}=await options(profile,'invalid-input');
  const result=await invokeDirect(profile,env,'{"incomplete":');
  assert.equal(result.code,1);assert.equal(result.stdout,'');assert.match(result.stderr,/SyntaxError/);
  await assert.rejects(fs.stat(calls),error=>error.code==='ENOENT');
 });
}
