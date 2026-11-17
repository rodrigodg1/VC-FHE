import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import path from 'node:path';
import {configuration,rpc,task,pull} from './client.mjs';
import {ethers,ownerTransaction} from '/app/threshold-kms/campaign/common.mjs';
export async function adjudicators(){
  const cfg=await configuration();
  return [1,2,3].map(i=>({address:cfg.identities[`adjudicator-${i}`]}));
}
class ParticipantSigner extends ethers.AbstractSigner{
  constructor(node,address,provider){super(provider);Object.assign(this,{node,address});}
  getAddress(){return Promise.resolve(this.address);}
  connect(provider){return new ParticipantSigner(this.node,this.address,provider);}
  signMessage(){throw Error('unstructured participant signatures are disabled');}
  signTypedData(){throw Error('certificates require local canonical verification');}
  async signTransaction(tx){return rpc(this.node,'transaction',{transaction:await ownerTransaction(tx)});}
}
export async function signers(provider){
  const cfg=await configuration();
  const requester=new ethers.Wallet((await fs.readFile('/identity/signing.hex','utf8')).trim(),provider);
  assert.equal(requester.address,cfg.identities['coordinator-1']);
  const remote=node=>new ParticipantSigner(node,cfg.identities[node],provider);
  return [requester,remote('operator-1'),...['auditor-1','auditor-2','auditor-3'].map(remote),
    ...['auditor-1','auditor-2','auditor-3'].map(remote)];
}
export async function ownerRequest(body){
  if(body.action==='benchmark'&&!body.distributedFragment){
    await Promise.all([0,1,2,3].map(index=>ownerRequest({...body,index,distributedFragment:true})));
    const dir=`/fixtures/${body.caseName}`;
    const pieces=await Promise.all([0,1,2,3].map(i=>fs.readFile(`${dir}/benchmark-owner-${i}.json`,'utf8').then(JSON.parse)));
    const result={...pieces[0],admissions:pieces[0].admissions.map((_,i)=>{
      const candidates=pieces.map(p=>p.admissions[i]).filter(Boolean);assert.equal(candidates.length,1);return candidates[0];
    }),generatorsMs:pieces.reduce((total,p)=>total+p.generatorsMs,0)};
    for(const p of pieces){assert.equal(p.datasetTag,result.datasetTag);assert.equal(p.dimension,result.dimension);}
    await fs.writeFile(`${dir}/benchmark-admissions.json`,JSON.stringify(result),{flag:'wx'});
    return {path:`${dir}/benchmark-admissions.json`};
  }
  const root=`/fixtures/${body.caseName}`,inputs=[root];
  // Exact-release evidence is public. Owner validators still derive approval
  // from their independently prepared context and the fixed chain quorum.
  if(body.action==='transaction'){
    for(const d of ['/release-evidence','/exchange']){
      for(const name of await fs.readdir(d))if(name.endsWith('.json'))inputs.push(d+'/'+name);
    }
  }
  const result=await task(`owner-${body.index+1}`,'owner-request',body,inputs,
    body.action==='benchmark'?[root+`/benchmark-owner-${body.index}.json`]:[]);
  return result.value;
}
export async function canonicalExecute(binary,args){
  const result=await task('operator-1','canonical-execute',{args},[args[1]],[args[2]]);
  return result.value;
}
export async function canonicalAudit(body,node='auditor-1'){
  if(body.replayDir.endsWith('baseline-0'))node='auditor-2';
  if(body.replayDir.endsWith('baseline-1'))node='auditor-3';
  const result=await task(node,'canonical-audit',body,[body.publicDir,body.operatorDir],[body.replayDir]);
  return result.value;
}
export async function pairedLinear(name,body){
  const result=await task('auditor-1','linear-'+name,{...body,aggregate:body.aggregate.map(String)},
    [body.coordinates,body.admissions],[]);
  return result.value;
}
export async function linearAggregate(coordinates,output){
  const result=await task('operator-1','linear-aggregate',{coordinates,output},[coordinates],output?[output]:[]);
  return result.value;
}
export async function bindContract(name,transactionHash){
  const targets=name==='CanonicalBountyFHEDisputeGame'||name==='BountyTraceAvailability'
    ?['operator-1','auditor-1','auditor-2','auditor-3']:name==='GroupedLinearVerification'?['operator-1']:[];
  await Promise.all(targets.map(node=>rpc(node,'bind-contract',{name,transactionHash})));
}
export async function prepareAudit({game,taskId,auditorAddress,index,supportsOperator,context,publicDir,operatorDir,caseName}){
  const cfg=await configuration();
  const node=Object.keys(cfg.identities).find(k=>k.startsWith('auditor-')&&cfg.identities[k].toLowerCase()===auditorAddress.toLowerCase());
  assert.ok(node);
  const result=await task(node,'audit-commit',{game:game.target,taskId,auditorAddress,index,supportsOperator,
    context,publicDir,operatorDir,caseName},[publicDir,operatorDir],[]);
  return result.value;
}
export async function waitRemoteFile(file,seconds){
  const cfg=await configuration();
  if(cfg.role!=='coordinator')return false;
  if(file==='/fixtures/prepared.json'){
    const deadline=Date.now()+seconds*1000;
    const publications=await Promise.all([1,2,3,4].map(async i=>{
      while(true){
        const r=await rpc(`owner-${i}`,'public-manifest',{paths:[file]});
        if(r.ready)return r;
        if(Date.now()>deadline)throw Error('distributed owners did not finish preparation');
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
    }));
    await pull('owner-1',publications[0].files);
    const prepared=JSON.parse(await fs.readFile(file,'utf8'));
    for(const item of prepared.cases){
      const r=await rpc('owner-1','public-manifest',{paths:[`/fixtures/${item.name}`]});
      assert.ok(r.ready);await pull('owner-1',r.files);
    }
    return true;
  }
  const match=/^\/exchange\/(wire|pre-reservation|responses)-(\d+)\.json$/.exec(file);
  if(!match)return false;
  const [,stage,digits]=match,index=Number(digits),inputs=[];
  if(stage==='wire')inputs.push(`/exchange/request-${index}.json`);
  if(stage==='responses'){
    const witnesses=(await fs.readdir('/release-evidence')).map(n=>'/release-evidence/'+n);
    await Promise.all([1,2,3,4].map(i=>task(`kms-${i}`,'kms-evidence',{},witnesses,[])));
    inputs.push(`/exchange/reserved-${index}.json`);
  }
  await task('recipient-1','recipient-exchange',{stage,index},inputs,[file]);
  return true;
}
export async function normalizePublic(binary,job,workDir){
  assert.equal(job.action,'normalize');
  const r=await task('operator-1','normalize',job,[job.aggregate,job.evaluationKey],[job.output]);
  return r.value;
}
export async function completeRecipient(){
  const application=JSON.parse(await fs.readFile('/reports/application.json','utf8'));
  assert.equal(application.status,'passed');
  await task('recipient-1','recipient-exchange',{stage:'complete',index:application.cases.length},['/exchange/complete.json'],[]);
}
export async function participantMeasurement({role,purpose,input,outputDir,measurementId,game,taskId}){
  let node,name,inputs,outputs=[];
  if(role==='adjudicator'){
    node=input.identityFile.replace(/^role:/,'');name='canonical-attest';
    inputs=[input.publicDir,input.operatorDir,input.contextFile];
    if(input.mode==='full')outputs=[input.replayDir];
    if(input.mode==='leaf')outputs=[input.outputFile];
  }else if(role==='operator'){
    node='operator-1';name='canonical-execute';inputs=[input.args[1]];outputs=[input.args[2]];
  }else if(role==='auditor'){
    const cfg=await configuration(),address=(await game.getAssignedAuditors(taskId))[0];
    node=Object.keys(cfg.identities).find(k=>k.startsWith('auditor-')&&cfg.identities[k].toLowerCase()===address.toLowerCase());
    assert.ok(node,'assigned auditor has no distributed endpoint');
    name='canonical-audit';inputs=[input.publicDir,input.operatorDir];outputs=[input.replayDir];
  }else throw Error('unsupported measured role');
  const response=await task(node,name,{...input,taskId},inputs,outputs),raw=response.measurement;
  assert.ok(raw,'participant resource measurement missing');
  await fs.mkdir(outputDir,{recursive:true});
  await fs.writeFile(`${outputDir}/${measurementId}.distributed.json`,JSON.stringify(response.event),{flag:'wx'});
  if(response.publicWorkerResources?.length)await fs.writeFile(`${outputDir}/${measurementId}.public.jsonl`,
    response.publicWorkerResources.map(r=>JSON.stringify(r)).join('\n')+'\n',{flag:'wx'});
  return {value:response.value,measurement:{schema:'role-process-resources-v1',measurementId,role,purpose,
    executionScope:'controller-only-remote-fhe-excluded',status:raw.exitCode===0?'completed':'failed',
    exitCode:raw.exitCode,signal:raw.signal,startedAt:raw.startedAt,finishedAt:raw.finishedAt,
    elapsedMs:raw.elapsedMs,resources:raw.resources,nativeFheElapsedMs:null,
    participant:node,host:response.event.host,transportIncluded:false}};
}
