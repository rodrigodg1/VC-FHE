// The coordinator schedules these fixed operations. There is no remote shell,
// arbitrary executable, generic signing oracle, or decryption operation.
import path from 'node:path';
import {publicPath} from './public-files.mjs';
const permissions={
  operator:['canonical-execute','linear-aggregate','normalize'],
  auditor:['canonical-audit','linear-proposed','linear-baseline','audit-commit'],
  adjudicator:['canonical-attest'],
  owner:['owner-request'],
  recipient:['recipient-exchange'],
  kms:['kms-evidence'],
};
export function authorizeTask(role,task){
  if(!permissions[role]?.includes(task?.name))throw Error('task not permitted for this role');
  if(!Array.isArray(task.files)||!Array.isArray(task.outputs))throw Error('public input/output manifest required');
  for(const row of task.files)publicPath(row.path);
  for(const output of task.outputs)publicPath(output);
  const body=task.body;
  if(!body||typeof body!=='object'||Array.isArray(body))throw Error('structured task body required');
  if(task.name==='canonical-execute'){
    const a=body.args;
    if(!Array.isArray(a)||!['execute-canonical','execute-canonical-fault-fixture'].includes(a[0])||
       a.length!==(a[0]==='execute-canonical'?3:5))throw Error('invalid canonical execution');
    publicPath(a[1]);publicPath(a[2]);
    if(a.length===5&&(!/^\d+$/.test(a[3])||!/^\d+$/.test(a[4])))throw Error('invalid fault fixture');
  }
  if(['canonical-audit','canonical-attest'].includes(task.name)){
    for(const key of ['publicDir','operatorDir'])publicPath(body[key]);
    if(task.name==='canonical-audit')publicPath(body.replayDir);
    else{
      if(!['context','full','leaf'].includes(body.mode))throw Error('invalid certificate mode');
      publicPath(body.contextFile);
      if(body.replayDir)publicPath(body.replayDir);
      if(body.outputFile)publicPath(body.outputFile);
    }
  }
  if(task.name==='normalize'){
    if(body.action!=='normalize'||body.evaluationKey!=='/keyset/evaluation-key.bin')throw Error('invalid public conversion');
    publicPath(body.aggregate);publicPath(body.output);
  }
  if(task.name==='audit-commit'){
    publicPath(body.publicDir);publicPath(body.operatorDir);
    if(typeof body.caseName!=='string'||!/^[A-Za-z0-9_-]+$/.test(body.caseName))throw Error('invalid audit case');
  }
  if(task.name.startsWith('linear-')){
    publicPath(body.coordinates);
    if(body.admissions)publicPath(body.admissions);
    if(body.output)publicPath(body.output);
  }
  if(task.name==='kms-evidence'&&task.files.some(row=>!row.path.startsWith('/release-evidence/')))
    throw Error('KMS transport admits release evidence only');
  for(const row of task.files){
    if(task.outputs.some(out=>row.path===out||out.startsWith(row.path+'/')))
      throw Error('output overwrites an input object');
  }
  return task;
}
export function localIdentity(request,cfg){
  if(request.identityFile!==`role:${cfg.node}`)throw Error('certificate routed to wrong adjudicator');
  return {...request,rpcUrl:cfg.rpcUrl,binary:'/usr/local/bin/kms-campaign',identityFile:'/identity/signing.hex'};
}
export function ownerIndex(body,cfg){
  if(body.index!==cfg.ownerIndex||!Number.isSafeInteger(body.index))throw Error('owner identity mismatch');
  if(!['transaction','bls','benchmark','bind-workflow'].includes(body.action))throw Error('unknown owner action');
  return body;
}
