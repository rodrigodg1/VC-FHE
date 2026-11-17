// Experimental admission does not alter contract deadlines or validity rules.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {task,configuration} from './client.mjs';
const exec=promisify(execFile);
export async function admitWork(work){
  const envelope=JSON.parse(await fs.readFile('/config/budget-runtime.json','utf8'));
  const elapsed=(Date.now()-Date.parse(envelope.startedAt))/3600000;
  // Leave the quoted per-case allowance to finish an admitted operation. This
  // cannot guarantee billing, but prevents starting another case at exhaustion.
  assert.ok(Number.isFinite(elapsed)&&elapsed>=0);
  assert.ok(elapsed+envelope.caseAllowanceHours<=envelope.plannedHours,
    'budget duration leaves insufficient allowance for another complete case');
  const projected=elapsed*envelope.hourlyUsd+envelope.fixedUpperUsd;
  assert.ok(projected+envelope.caseAllowanceHours*envelope.hourlyUsd+envelope.reserveUsd<=envelope.maximumUsd,
    'remaining budget does not admit another complete case');
  const disk=await fs.statfs('/fixtures');
  assert.ok(disk.bavail*disk.bsize>=envelope.minimumFreeBytes,'insufficient free evidence storage');
  await fs.appendFile('/reports/distributed/admissions.jsonl',JSON.stringify({work,elapsedHours:elapsed,
    projectedUsd:projected,caseAllowanceHours:envelope.caseAllowanceHours,admitted:true})+'\n');
}
export async function verifyBytes(cfg,prepared){
  await admitWork({phase:'cross-host-byte-repeatability'});
  const {createExecutionContext}=await import('/app/threshold-kms/campaign/runtime/scripts/canonical-protocol.mjs');
  const selected=prepared.cases.filter(c=>c.half==='nonlinear').sort((a,b)=>b.n-a.n||Number(b.regional)-Number(a.regional));
  assert.ok(selected.length);
  const item=selected[0],dir='/fixtures/'+item.name,publicDir=dir+'/public';
  const program=JSON.parse(await fs.readFile(publicDir+'/program.json','utf8'));
  const context=await createExecutionContext({binary:'/usr/local/bin/kms-campaign',publicDir,
    keyEpoch:prepared.keys.keyEpoch,policyDomain:cfg.policyDomain,inputBounds:item.inputBounds,
    records:program.inputs.map((r,i)=>({id:r.id,protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
  const operatorDir=dir+'/wan-admission-operator';
  const operator=await task('operator-1','canonical-execute',{args:['execute-canonical',publicDir,operatorDir]},[publicDir],[operatorDir]);
  const audits=[];
  for(const node of ['auditor-1','auditor-2','auditor-3']){
    const replayDir=dir+'/wan-admission-'+node;
    const response=await task(node,'canonical-audit',{context,publicDir,operatorDir,replayDir},[publicDir,operatorDir],[replayDir]);
    assert.equal(response.value.index,null);assert.equal(response.value.operatorRoot,response.value.replayRoot);
    assert.equal(response.value.plaintextOpenings,0);
    audits.push({node,eventId:response.event.id,evidence:response.value});
  }
  await fs.writeFile('/reports/distributed/byte-repeatability.json',JSON.stringify({schema:'vcfhe-cross-host-bytes-v1',
    status:'passed',caseName:item.name,records:item.n,operatorEventId:operator.event.id,audits,
    includedInMeasurements:false,plaintextOpenings:0}),{flag:'wx'});
}
