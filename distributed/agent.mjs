import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createRoleServer} from './role-transport.mjs';
import {manifest,install,putBlob,blobId} from './public-files.mjs';
import {authorizeTask,ownerIndex} from './adapter-policy.mjs';
const cfg=JSON.parse(await fs.readFile(process.env.VCFHE_ROLE_CONFIG??'/config/role.json','utf8'));
const cas='/transport/public-chunks';
let transactions;
async function transactionService(){
  if(!['operator','auditor'].includes(cfg.role))throw Error('transaction signer unavailable for this role');
  return transactions??=await (await import('./transaction-adapter.mjs')).transactionAdapter(cfg);
}
let running=false;
async function computed(task,id){
  const report='/reports/distributed/'+id+'.resources.json';
  const publicMetrics='/reports/distributed/'+id+'.public.jsonl';
  const measurement=await new Promise((resolve,reject)=>{
    const child=spawn('python3',['/app/threshold-kms/campaign/measure-process.py','--report',report,'--',
      process.execPath,'/app/distributed/worker.mjs'],{stdio:['pipe','pipe','pipe'],
      env:{...process.env,RAYON_NUM_THREADS:'1',VCFHE_DISTRIBUTED_WORKER:'1',VCFHE_PUBLIC_WORKER_METRICS_FILE:publicMetrics}});
    let out='',error='';
    child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>error+=b);
    child.on('error',reject);child.on('close',code=>{
      if(code!==0){console.error(error);reject(Error('participant computation failed'));}
      else{try{resolve(JSON.parse(out));}catch(e){reject(e);}}
    });
    child.stdin.end(JSON.stringify({task,cfg:{...cfg,requestId:id}}));
  });
  let publicWorkerResources=[];
  try{publicWorkerResources=(await fs.readFile(publicMetrics,'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);}
  catch(e){if(e.code!=='ENOENT')throw e;}
  return {value:measurement,measurement:JSON.parse(await fs.readFile(report,'utf8')),publicWorkerResources};
}
const handlers={
  'bind-contract':async body=>(await transactionService()).bind(body),
  transaction:async body=>(await transactionService()).sign(body),
  'public-manifest':async({paths})=>{
    if(!Array.isArray(paths)||paths.length>128)throw Error('bounded public paths required');
    try{return {ready:true,files:await manifest(paths,{cas})};}
    catch(e){if(e.code==='ENOENT')return {ready:false};throw e;}
  },
  'missing-chunks':async({ids})=>{
    if(!Array.isArray(ids)||ids.length>256)throw Error('bounded chunk list required');
    const missing=[];
    for(const id of ids){blobId(id);try{await fs.access(path.join(cas,id));}catch(e){if(e.code!=='ENOENT')throw e;missing.push(id);}}
    return missing;
  },
  'put-chunk':async({id,data})=>{await putBlob(cas,id,Buffer.from(data,'base64'));return{id};},
  'get-chunk':async({id})=>({id:blobId(id),data:(await fs.readFile(path.join(cas,id))).toString('base64')}),
  task:async(task,request)=>{
    authorizeTask(cfg.role,task);
    if(running)throw Error('participant already executing a task');
    running=true;
    await fs.mkdir('/reports/distributed',{recursive:true});
    const start=performance.now();
    try{
      if(task.name==='owner-request'){
        // Never let coordinator uploads race local encryption/context approval.
        // Only the owner process can produce this initial marker.
        await fs.access('/fixtures/prepared.json');
        if(task.files.some(row=>!row.path.startsWith('/fixtures/')&&!row.path.startsWith('/exchange/')&&
          !row.path.startsWith('/release-evidence/')))throw Error('owner request cannot change public keys');
        if(task.files.some(row=>row.path==='/fixtures/prepared.json'))throw Error('coordinator cannot replace owner preparation');
      }
      await install(task.files,cas);
      let result;
      if(task.name==='kms-evidence')result={value:{installed:task.files.length},measurement:null};
      else if(task.name==='owner-request'){
        const body=ownerIndex(task.body,cfg);
        const {atomic,waitFile}=await import('/app/threshold-kms/campaign/common.mjs');
        const queue='/owner-rpc/'+request.id;
        await atomic(queue+'.request',body);
        const reply=await waitFile(queue+'.response',cfg.timeoutSeconds??14400);
        if(reply.error)throw Error(reply.error);
        result={value:reply.value,measurement:null};
      }else if(task.name==='recipient-exchange'){
        const {waitFile}=await import('/app/threshold-kms/campaign/common.mjs');
        if(!Number.isSafeInteger(task.body.index)||task.body.index<0||
           !['wire','pre-reservation','responses','complete'].includes(task.body.stage))throw Error('invalid recipient exchange stage');
        if(task.body.stage!=='complete')await waitFile(`/exchange/${task.body.stage}-${task.body.index}.json`,cfg.timeoutSeconds??14400);
        result={value:{stage:task.body.stage,index:task.body.index},measurement:null};
      }else result=await computed(task,request.id);
      const files=await manifest(task.outputs,{cas});
      const event={schema:'vcfhe-distributed-task-v1',id:request.id,campaign:cfg.campaign,host:cfg.host,
        node:cfg.node,role:cfg.role,task:task.name,status:'completed',elapsedMs:performance.now()-start,
        taskId:task.body.taskId??null,mode:task.body.mode??null,
        caseId:task.files.map(row=>/^\/fixtures\/([^/]+)/.exec(row.path)?.[1]).find(Boolean)??null,
        requestBodySha256:createHash('sha256').update(JSON.stringify(task.body)).digest('hex'),
        resultSha256:createHash('sha256').update(JSON.stringify(result.value,(_,v)=>typeof v==='bigint'?String(v):v)).digest('hex'),
        inputs:task.files,outputs:files,measurement:result.measurement,publicWorkerResources:result.publicWorkerResources??[]};
      await fs.writeFile('/reports/distributed/'+request.id+'.task.json',JSON.stringify(event,null,2),{flag:'wx'});
      return {...result,files,event};
    }catch(e){
      await fs.writeFile('/reports/distributed/'+request.id+'.failure.json',JSON.stringify({id:request.id,
        campaign:cfg.campaign,host:cfg.host,node:cfg.node,role:cfg.role,task:task.name,status:'failed',
        elapsedMs:performance.now()-start,errorType:e.name}),{flag:'wx'});
      console.error(e);throw e;
    }finally{running=false;}
  },
};
const server=createRoleServer({campaign:cfg.campaign,node:cfg.node,
  key:await fs.readFile(cfg.tls.key),cert:await fs.readFile(cfg.tls.cert),ca:await fs.readFile(cfg.tls.ca),
  peers:cfg.peers,journal:'/transport/journal',handlers});
server.listen(cfg.port,'0.0.0.0',()=>console.log(JSON.stringify({role:cfg.node,state:'listening',port:cfg.port})));
