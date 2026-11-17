import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {runPublicFheProcess,publicFheResourceObservation,publicWorkerMetricsFile,recordPublicWorkerResources} from './public-worker-resources.mjs';

const dir=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-public-worker-resource-tests-'));
const binary=path.join(dir,'fake-public-fhe-worker');
await fs.writeFile(binary,`#!/usr/bin/env node
const fs=require('node:fs'),assert=require('node:assert/strict');
assert.deepEqual(process.argv.slice(2),['tops_public_fhe_worker','--exact','--nocapture','--test-threads=1']);
assert.equal(process.env.RAYON_NUM_THREADS,'1');
const job=JSON.parse(fs.readFileSync(process.env.TOPS_FHE_WORKER_JOB,'utf8'));
fs.appendFileSync(job.counter,'invoked\\n');
const start=Date.now();while(Date.now()-start<20){}
if(job.fail){console.error('fixture worker failed');process.exit(7);}
fs.writeFileSync(job.output,JSON.stringify({canonicalOutput:'unchanged'}));
console.log('running 1 test\\ntest tops_public_fhe_worker ... ok\\ntest result: ok');
`,{mode:0o700});
async function fixture(name,fail=false){
 const jobFile=path.join(dir,name+'.job.json'),resourceFile=path.join(dir,name+'.resources.json');
 const job={output:path.join(dir,name+'.output.json'),counter:path.join(dir,name+'.counter'),fail};
 await fs.writeFile(jobFile,JSON.stringify(job));return {binary,jobFile,resourceFile,job};
}

test('measurement wraps the original test-harness invocation once without parsing stdout as JSON',async()=>{
 const f=await fixture('measured');
 const raw=await runPublicFheProcess({...f,collectResources:true});
 assert.equal(raw.exitCode,0);assert.ok(raw.elapsedMs>0);assert.ok(raw.resources.totalCpuMs>0);
 assert.equal(raw.resources.scope,'command-and-waited-descendants');
 assert.deepEqual(JSON.parse(await fs.readFile(f.job.output,'utf8')),{canonicalOutput:'unchanged'});
 assert.equal(await fs.readFile(f.job.counter,'utf8'),'invoked\n');
 assert.equal(JSON.parse(await fs.readFile(f.resourceFile,'utf8')).exitCode,0);
});

test('unmeasured invocation preserves the existing output and creates no resource evidence',async()=>{
 const f=await fixture('unmeasured');
 assert.equal(await runPublicFheProcess(f),undefined);
 assert.deepEqual(JSON.parse(await fs.readFile(f.job.output,'utf8')),{canonicalOutput:'unchanged'});
 assert.equal(await fs.readFile(f.job.counter,'utf8'),'invoked\n');
 await assert.rejects(fs.stat(f.resourceFile),error=>error.code==='ENOENT');
});

test('failed Rust-shaped subprocess retains CPU evidence and its actual failure status',async()=>{
 const f=await fixture('failed',true);let raw;
 await assert.rejects(runPublicFheProcess({...f,collectResources:true}),error=>{
  raw=error.publicFheResources;return raw?.exitCode===7&&raw.resources.totalCpuMs>0;
 });
 const observation=publicFheResourceObservation(raw,{requestId:'failed-request',job:{action:'kms-circuit',args:[binary,'leaf']}});
 assert.equal(observation.status,'failed');assert.equal(observation.operation,'leaf');
 const sink=path.join(dir,'failed.ndjson');
 await recordPublicWorkerResources({error:'fixture worker failed',resourceMeasurement:observation},sink);
 assert.equal(JSON.parse((await fs.readFile(sink,'utf8')).trim()).exitCode,7);
});

test('request labels and actual process resources remain separate from caller role labels',async()=>{
 const f=await fixture('labelled'),raw=await runPublicFheProcess({...f,collectResources:true});
 const observation=publicFheResourceObservation(raw,{requestId:'rpc-1',job:{action:'kms-circuit',args:[binary,'execute-canonical']}});
 assert.equal(observation.schema,'public-fhe-process-resources-v1');assert.equal(observation.operation,'execute-canonical');
 assert.equal(Object.hasOwn(observation,'role'),false);
 assert.equal(Object.hasOwn(observation,'taskId'),false);
 const sink=path.join(dir,'labelled.ndjson');await recordPublicWorkerResources({passed:true,resourceMeasurement:observation},sink);
 assert.deepEqual(JSON.parse((await fs.readFile(sink,'utf8')).trim()),observation);
});

test('an existing resource report cannot rerun the command or be relabelled as fresh evidence',async()=>{
 const f=await fixture('collision');await runPublicFheProcess({...f,collectResources:true});
 const before=await fs.readFile(f.resourceFile,'utf8');
 await assert.rejects(runPublicFheProcess({...f,collectResources:true}),/refusing to reuse/);
 assert.equal(await fs.readFile(f.job.counter,'utf8'),'invoked\n');
 assert.equal(await fs.readFile(f.resourceFile,'utf8'),before);
});

test('optional client instrumentation requires an absolute sink and successful responses must include resources',async()=>{
 assert.equal(publicWorkerMetricsFile({}),undefined);
 assert.equal(publicWorkerMetricsFile({VCFHE_PUBLIC_WORKER_METRICS_FILE:path.join(dir,'client.ndjson')}),path.join(dir,'client.ndjson'));
 assert.throws(()=>publicWorkerMetricsFile({VCFHE_PUBLIC_WORKER_METRICS_FILE:'relative.ndjson'}),/absolute/);
 await assert.rejects(recordPublicWorkerResources({passed:true},path.join(dir,'missing.ndjson')),/missing requested/);
 // Invalid requests rejected before execution have no Rust resource observation.
 await recordPublicWorkerResources({error:'unmounted circuit path'},path.join(dir,'pre-execution.ndjson'));
 await assert.rejects(fs.stat(path.join(dir,'pre-execution.ndjson')),error=>error.code==='ENOENT');
});
