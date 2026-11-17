import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {normalizeLocally} from '../normalization.mjs';
import {distributedEncrypt} from '../owner-fragments.mjs';

async function fixture(){
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-normalization-test-'));
  const binary=path.join(directory,'fake-public-worker');
  // This fake subprocess tests adapter dispatch and errors, not FHE correctness.
  await fs.writeFile(binary,`#!/usr/bin/env node
const fs=require('node:fs');
const job=JSON.parse(fs.readFileSync(process.env.TOPS_FHE_WORKER_JOB,'utf8'));
if(job.fail)process.exit(22);
if(process.env.RAYON_NUM_THREADS!=='1')process.exit(23);
fs.writeFileSync(job.output,JSON.stringify(job));
`,{mode:0o700});
  return {directory,binary,cleanup:()=>fs.rm(directory,{recursive:true,force:true})};
}

test('operator conversion returns JSON only after the original worker completes',async()=>{
  const f=await fixture();
  try{
    const job={action:'normalize',output:path.join(f.directory,'output.json'),plan:{weights:[1,2]}};
    const result=await normalizeLocally(f.binary,job,path.join(f.directory,'jobs'));
    assert.deepEqual(JSON.parse(JSON.stringify(result)),{status:'completed',action:'normalize'});
    assert.deepEqual(JSON.parse(await fs.readFile(job.output,'utf8')),job);
  }finally{await f.cleanup();}
});

test('owner conversion does not require encryption indices or a role configuration',async()=>{
  const f=await fixture();
  try{
    const job={action:'normalize',output:path.join(f.directory,'owner-output.json'),plan:{weights:[1]}};
    const result=await distributedEncrypt(f.binary,job,path.join(f.directory,'owner-jobs'));
    assert.equal(result.status,'completed');
    assert.deepEqual(JSON.parse(await fs.readFile(job.output,'utf8')),job);
  }finally{await f.cleanup();}
});

test('failed native conversion propagates and cannot return a completion record',async()=>{
  const f=await fixture();
  try{
    const job={action:'normalize',fail:true,output:path.join(f.directory,'absent.json')};
    await assert.rejects(normalizeLocally(f.binary,job,path.join(f.directory,'jobs')),e=>e.code===22);
    await assert.rejects(fs.access(job.output),e=>e.code==='ENOENT');
    await assert.rejects(distributedEncrypt(f.binary,job,path.join(f.directory,'owner-jobs')),e=>e.code===22);
  }finally{await f.cleanup();}
});
