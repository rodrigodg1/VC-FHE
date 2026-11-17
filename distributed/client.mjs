import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {AsyncLocalStorage} from 'node:async_hooks';
import {callRole} from './role-transport.mjs';
import {manifest,install,putBlob,blobId} from './public-files.mjs';
let configured;
const transferScope=new AsyncLocalStorage();
export async function configuration(){
  return configured??=JSON.parse(await fs.readFile(process.env.VCFHE_ROLE_CONFIG??'/config/role.json','utf8'));
}
export async function rpc(target,operation,body,{id=randomUUID(),timeoutMs=14_400_000}={}){
  body=JSON.parse(JSON.stringify(body,(_,value)=>typeof value==='bigint'?value.toString():value));
  const cfg=await configuration(),peer=cfg.peers.find(p=>p.node===target);
  if(!peer)throw Error('unknown role '+target);
  const result=await callRole({url:peer.url,request:{id,campaign:cfg.campaign,target,sender:cfg.node,operation,body},
    key:await fs.readFile(cfg.tls.key),cert:await fs.readFile(cfg.tls.cert),ca:await fs.readFile(cfg.tls.ca),
    serverFingerprint256:peer.fingerprint256,timeoutMs});
  await fs.mkdir('/reports/distributed',{recursive:true});
  await fs.appendFile('/reports/distributed/transport.jsonl',JSON.stringify({schema:'vcfhe-role-transport-v1',kind:'role_transport',
    campaign:cfg.campaign,host:cfg.host,node:cfg.node,target,operation,id,...result.metrics,
    ...transferScope.getStore(),
    handlerSeconds:result.response.handlerSeconds})+'\n');
  return result.response.value;
}
const CHUNK_CONCURRENCY=8;
// Shared across concurrent transfers in this process. Control RPCs do not use
// these slots. No buffer for a pending chunk is allocated before admission.
let chunkActive=0;
const chunkWaiters=[];
async function chunkSlot(action){
  if(chunkActive<CHUNK_CONCURRENCY)chunkActive++;
  else await new Promise(resolve=>chunkWaiters.push(resolve));
  try{return await action();}
  finally{const next=chunkWaiters.shift();if(next)next();else chunkActive--;}
}
async function forEachChunk(values,action){
  let index=0,failed=false,failure;
  await Promise.all(Array.from({length:Math.min(CHUNK_CONCURRENCY,values.length)},async()=>{
    while(!failed){
      const current=index++;if(current>=values.length)return;
      try{await chunkSlot(async()=>{if(!failed)await action(values[current]);});}
      catch(error){if(!failed){failed=true;failure=error;}}
    }
  }));
  // Drain every admitted operation before reporting failure. A caller cannot
  // start its task/install while a rejected transfer is still writing chunks.
  if(failed)throw failure;
}
const cache='/transport/public-chunks';
export async function push(target,paths){
  const rows=await manifest(paths,{cas:cache});
  const ids=[...new Set(rows.flatMap(r=>r.chunks))];
  // Bound manifest/query size even for very large traces.
  for(let i=0;i<ids.length;i+=256){
    const missing=await rpc(target,'missing-chunks',{ids:ids.slice(i,i+256)});
    for(const id of missing){
      blobId(id);
      if(!ids.includes(id))throw Error('peer requested a chunk outside this manifest');
    }
    await forEachChunk([...new Set(missing)],async id=>{
      await rpc(target,'put-chunk',{id,data:(await fs.readFile(path.join(cache,id))).toString('base64')});
    });
  }
  return rows;
}
export async function pull(target,rows){
  await forEachChunk([...new Set(rows.flatMap(r=>r.chunks))],async id=>{
    blobId(id);
    try{await fs.access(path.join(cache,id));}
    catch(e){if(e.code!=='ENOENT')throw e;const value=await rpc(target,'get-chunk',{id});await putBlob(cache,id,Buffer.from(value.data,'base64'));}
  });
  await install(rows,cache);
}
export async function task(target,name,body,inputs=[],outputs=[]){
  const phaseId=randomUUID();
  const caseId=inputs.map(p=>/^\/fixtures\/([^/]+)/.exec(p)?.[1]).find(Boolean)??null;
  return transferScope.run({phaseId,case_id:caseId,task:name},async()=>{
    const files=await push(target,inputs);
    const result=await rpc(target,'task',{name,body,files,outputs},{id:phaseId});
    await pull(target,result.files);
    return result;
  });
}
