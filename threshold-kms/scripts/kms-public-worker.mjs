import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec = promisify(execFile);
export async function runPublicWorker(binary, job, directory) {
  await fs.mkdir(directory,{recursive:true});
  const file=path.join(directory,`${randomUUID()}.job.json`);
  await fs.writeFile(file,JSON.stringify(job),{flag:'wx'});
  const env={...process.env,RAYON_NUM_THREADS:'1',TOPS_FHE_WORKER_JOB:file};
  delete env.TOPS_KMS_GATEWAY_TOKEN;
  await exec(binary,['tops_public_fhe_worker','--exact','--nocapture','--test-threads=1'],
    {env,maxBuffer:4*1024*1024,timeout:3600000});
}
export async function runKmsCircuit(binary,args) {
  const directory=path.join(path.dirname(args[1]),'.worker-jobs');
  const result=path.join(directory,`${randomUUID()}.result.json`);
  await runPublicWorker(binary,{action:'kms-circuit',args:[binary,...args],result},directory);
  return JSON.parse(await fs.readFile(result,'utf8'));
}
