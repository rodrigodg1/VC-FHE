// Measurement belongs around the Rust subprocess in the networkless worker.
// Resource usage of a Node client waiting on worker RPC excludes this work.
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
const exec=promisify(execFile);
const helper=fileURLToPath(new URL('./measure-process.py',import.meta.url));
export const PUBLIC_FHE_RESOURCE_SCHEMA='public-fhe-process-resources-v1';

export async function runPublicFheProcess({binary,jobFile,resourceFile,collectResources=false,env=process.env}){
 const args=['tops_public_fhe_worker','--exact','--nocapture','--test-threads=1'];
 const options={env:{...env,RAYON_NUM_THREADS:'1',TOPS_FHE_WORKER_JOB:jobFile},
  timeout:14400000,maxBuffer:4*1024*1024};
 if(!collectResources){await exec(binary,args,options);return undefined;}
 if(!path.isAbsolute(resourceFile))throw Error('absolute worker resource path required');
 try{await fs.access(resourceFile);throw Error('refusing to reuse public FHE resource evidence');}
 catch(error){if(error.code!=='ENOENT')throw error;}
 let failure;
 try{await exec('python3',[helper,'--report',resourceFile,'--',binary,...args],options);}
 catch(error){failure=error;}
 let resources;
 try{resources=JSON.parse(await fs.readFile(resourceFile,'utf8'));}
 catch(cause){throw new Error('public FHE resource report unavailable',{cause:failure??cause});}
 if(failure){failure.publicFheResources=resources;throw failure;}
 return resources;
}

export function publicFheResourceObservation(raw,{requestId,job}){
 return {schema:PUBLIC_FHE_RESOURCE_SCHEMA,requestId,action:job.action,
  operation:job.action==='kms-circuit'?job.args[1]:job.action,
  status:raw.exitCode===0?'completed':'failed',exitCode:raw.exitCode,signal:raw.signal,
  startedAt:raw.startedAt,finishedAt:raw.finishedAt,elapsedMs:raw.elapsedMs,resources:raw.resources};
}

export function publicWorkerMetricsFile(env=process.env){
 const file=env.VCFHE_PUBLIC_WORKER_METRICS_FILE;
 if(file===undefined)return undefined;
 if(typeof file!=='string'||!path.isAbsolute(file))throw Error('absolute public worker metrics file required');
 return file;
}
export async function recordPublicWorkerResources(response,file){
 if(file===undefined)return;
 const observation=response.resourceMeasurement;
 if(!observation&&response.error)return; // Rejected before a subprocess started.
 if(!observation||observation.schema!==PUBLIC_FHE_RESOURCE_SCHEMA)
  throw Error('public worker response is missing requested resource evidence');
 await fs.appendFile(file,JSON.stringify(observation)+'\n',{mode:0o600});
}
