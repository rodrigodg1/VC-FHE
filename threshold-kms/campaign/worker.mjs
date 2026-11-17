import fs from 'node:fs/promises';
import path from 'node:path';
import {atomic,json} from './common.mjs';
import {runPublicFheProcess,publicFheResourceObservation} from './public-worker-resources.mjs';
const binary='/usr/local/bin/kms-campaign';
const allowed=p=>typeof p==='string'&&(path.resolve(p).startsWith('/fixtures/')||path.resolve(p).startsWith('/keyset/'));
async function handle(request,id){
 const {job,directory}=request;
 if(request.collectResources!==undefined&&request.collectResources!==true)throw Error('invalid resource collection flag');
 if(!allowed(directory)||Object.hasOwn(job,'values'))throw Error('private/outside worker request');
 if(job.action==='normalize'){
  if(![job.evaluationKey,job.aggregate,job.output].every(allowed))throw Error('unmounted linear path');
 }else if(job.action==='kms-circuit'){
  if(!['execute-canonical','execute-canonical-fault-fixture','leaf'].includes(job.args?.[1])||!allowed(job.result))throw Error('unsupported circuit action');
  if(!job.args.slice(2).every(v=>allowed(v)||/^[0-9]+$/.test(v)))throw Error('unmounted circuit path');
 }else throw Error('unsupported public worker action');
 await fs.mkdir(directory,{recursive:true});const file=directory+'/'+id+'.job.json';await atomic(file,job);
 try{
  const raw=await runPublicFheProcess({binary,jobFile:file,collectResources:request.collectResources===true,
   resourceFile:'/worker-rpc/'+id+'.resources.json'});
  return raw?publicFheResourceObservation(raw,{requestId:id,job}):undefined;
 }catch(error){
  if(error.publicFheResources)error.resourceMeasurement=publicFheResourceObservation(error.publicFheResources,{requestId:id,job});
  throw error;
 }
}
while(true){
 for(const name of await fs.readdir('/worker-rpc'))if(name.endsWith('.request')){
  const result='/worker-rpc/'+name.replace('.request','.response');try{await fs.access(result);continue;}catch{}
  let value;try{
   const resourceMeasurement=await handle(await json('/worker-rpc/'+name),name.slice(0,-8));
   value={passed:true,...(resourceMeasurement?{resourceMeasurement}:{})};
  }catch(e){value={error:String(e),...(e.resourceMeasurement?{resourceMeasurement:e.resourceMeasurement}:{})};}
  await atomic(result,value);
 }
 await new Promise(r=>setTimeout(r,100));
}
