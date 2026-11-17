// Networkless public worker; no owner, gateway, recipient or core private mount.
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {atomic,waitFile} from './common.mjs';
import {publicWorkerMetricsFile,recordPublicWorkerResources} from './public-worker-resources.mjs';
export async function runPublicWorker(binary,job,directory){
 if(!['normalize','kms-circuit'].includes(job.action)||Object.hasOwn(job,'values'))throw Error('not a public evaluation job');
 const metricsFile=publicWorkerMetricsFile();
 const id=randomUUID();await atomic(`/worker-rpc/${id}.request`,{job,directory,...(metricsFile?{collectResources:true}:{})});
 const response=await waitFile(`/worker-rpc/${id}.response`);
 // Preserve failed Rust resource observations before propagating the job error.
 await recordPublicWorkerResources(response,metricsFile);
 if(response.error)throw Error(response.error);
}
export async function runKmsCircuit(binary,args){
 const directory=path.join(path.dirname(args[1]),'.worker-jobs');await fs.mkdir(directory,{recursive:true});
 const result=path.join(directory,randomUUID()+'.result.json');
 await runPublicWorker(binary,{action:'kms-circuit',args:[binary,...args],result},directory);
 return JSON.parse(await fs.readFile(result,'utf8'));
}
